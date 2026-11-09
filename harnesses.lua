-- The agent harnesses barbasol_can can move, loaded with dofile by init.lua (on
-- the Rex server, to find the pane's session) and by move.lua (to move it).
--
-- Each harness has:
--   match(fg)             true if the pane's foreground process is this harness
--   session(fg, title)    the session that process is in, as id, cwd, and its title if
--                         known; or nil, why. title is the pane's terminal title.
--   export                sh script, $1 = id, $2 = cwd: writes a tar.gz of the session to stdout
--   bin                   the agent's command, which the target must have
--   import                sh script run on the target after the tar.gz is unpacked into $t,
--                         with $id and $to (the target directory) set; calls fail "<why>"
--                         on failure, and resumed just before it execs the agent
--
-- session() reads what the harness itself records about a running process, so
-- it names the session that pane is in rather than the newest one in the folder.
local HOME = os.getenv("HOME")

local function sh(script, ...)
  local r = rex.exec({ "sh", "-c", script, "sh", ... })
  return r and r.ok and r.stdout or ""
end

local function readfile(path)
  local f = io.open(path)
  if not f then return nil end
  local s = f:read("*a")
  f:close()
  return s
end

-- Seconds the process has been running, from ps etime ([[dd-]hh:]mm:ss).
local function age(pid)
  local e = sh('ps -o etime= -p "$1"', tostring(pid)):match("%S+")
  if not e then return nil end
  local d, rest = e:match("^(%d+)%-(.*)$")
  local n = 0
  for part in (rest or e):gmatch("%d+") do n = n * 60 + tonumber(part) end
  return n + (tonumber(d) or 0) * 86400
end

local function args(pid) return sh('ps -o args= -p "$1"', tostring(pid)) end

-- 2026-11-08T06:35:25.882Z to Unix seconds, without going through the local time zone.
local function utc(iso)
  local y, m, d, H, M, S = iso:match("^(%d+)%-(%d+)%-(%d+)T(%d+):(%d+):(%d+)")
  if not y then return nil end
  y, m, d = tonumber(y), tonumber(m), tonumber(d)
  if m <= 2 then y = y - 1 end
  local era = math.floor(y / 400)
  local yoe = y - era * 400
  local doy = math.floor((153 * (m + (m > 2 and -3 or 9)) + 2) / 5) + d - 1
  local days = era * 146097 + yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy - 719468
  return days * 86400 + tonumber(H) * 3600 + tonumber(M) * 60 + tonumber(S)
end

local H = {}

-- True for `codex exec …`, the non-interactive mode, judged by the subcommand
-- rather than the word appearing anywhere (such as in a prompt).
function H.codex_exec(args) return (args .. " "):match("^%S+%s+exec%s") ~= nil end
H.utc = utc

H.claude = {
  bin = "claude",
  match = function(fg) return fg.name == "claude" end,
  -- Claude Code records each running instance at ~/.claude/sessions/<pid>.json.
  session = function(fg)
    local s = rex.json.decode(readfile(HOME .. "/.claude/sessions/" .. fg.pid .. ".json") or "null")
    if not (s and s.sessionId) then return nil, "Claude Code has no session record for this process" end
    return s.sessionId, s.cwd, s.nameSource ~= "derived" and s.name or nil
  end,
  -- Sessions live under the project's cwd with every non-alphanumeric as "-",
  -- with subagent transcripts and tool results in a sibling <id>/ directory.
  export = [[
cd "$HOME/.claude/projects/$(printf %s "$2" | sed 's/[^a-zA-Z0-9]/-/g')" &&
tar czf - "$1.jsonl" $(test -d "$1" && echo "$1")
]],
  import = [[
p="$HOME/.claude/projects/$(printf %s "$to" | sed 's/[^a-zA-Z0-9]/-/g')"
mkdir -p "$p" && cp -R "$t"/. "$p"/ || fail "couldn't copy the session into $p"
cd "$to" || fail "no directory $to"
resumed; exec claude --resume "$id"
]],
}

H.codex = {
  bin = "codex",
  match = function(fg) return fg.name == "codex" end,
  -- Three records, most current first:
  --  * An in-process Codex logs to ~/.codex/logs_2.sqlite with pid:<pid>:<uuid>
  --    and the thread on each line. (When threads run in Codex's shared
  --    app-server daemon, they're logged under the daemon's pid instead.)
  --  * The pane title is "<thread name> | <dir>", and the thread's name is in
  --    the threads table, so it picks out the thread among those in this cwd.
  --  * `codex resume <id>` has it in the arguments before the title is set.
  -- A fresh Codex has no thread until its first turn.
  session = function(fg, title)
    local a = args(fg.pid)
    if H.codex_exec(a) then return nil, "codex exec runs non-interactively" end
    local function q(s) return "'" .. s:gsub("'", "''") .. "'" end
    local function sql(db, query) return sh('sqlite3 "$HOME/.codex/$1" "$2"', db, query) end
    local since = os.time() - (age(fg.pid) or 0) - 2
    local id = sql("logs_2.sqlite", string.format(
      "select thread_id from logs where process_uuid like 'pid:%d:%%' and thread_id is not null and ts >= %d order by id desc limit 1",
      fg.pid, since)):match("[%x%-]+")
    local name = title and title:match("^(.-) | [^|]*$")
    if not id and name and name ~= "" then
      local ids = {}
      for i in sql("state_5.sqlite", "select id from threads where cwd = " .. q(fg.cwd) .. " and name = " .. q(name)):gmatch("[%x%-]+") do
        ids[#ids + 1] = i
      end
      if #ids > 1 then return nil, "several threads here are named \"" .. name .. "\"" end
      id = ids[1]
    end
    id = id or a:match("resume%s+(%x+%-%x+%-%x+%-%x+%-%x+)")
    if not id then return nil, "Codex hasn't started a thread yet; send a message first" end
    local tname = sql("state_5.sqlite", "select coalesce(nullif(name, ''), title) from threads where id = " .. q(id)):gsub("\n$", "")
    return id, fg.cwd, tname ~= "" and tname or nil
  end,
  -- A thread is one rollout file under ~/.codex/sessions/YYYY/MM/DD/; the state
  -- databases beside it are indexes Codex rebuilds from those files.
  export = [[
f=$(find "$HOME/.codex/sessions" -name "rollout-*-$1.jsonl" | head -n 1)
test -n "$f" || { echo "no rollout for $1" >&2; exit 1; }
cd "$HOME/.codex" && tar czf - "${f#$HOME/.codex/}"
]],
  import = [[
mkdir -p "$HOME/.codex" && cp -R "$t"/. "$HOME/.codex"/ || fail "couldn't copy the thread into ~/.codex"
cd "$to" || fail "no directory $to"
resumed; exec codex resume -C "$to" "$id"
]],
}

H.opencode = {
  bin = "opencode",
  match = function(fg) return fg.name == "opencode" end,
  -- opencode processes share one log and tag their lines run=<id>. A run starts
  -- with "creating instance" for its directory, at the process's start time, and
  -- logs session.id= when it works on a session. Without a turn yet, -s <id> in
  -- its arguments names the session. The pane title ("OC | <title>") must agree.
  session = function(fg, title)
    local start = os.time() - (age(fg.pid) or 0)
    local runs, sid, run = {}, {}, nil
    local log = io.open(HOME .. "/.local/share/opencode/log/opencode.log")
    for line in (log and log:lines() or function() end) do
      local ts, r = line:match("^timestamp=(%S+) level=%S+ run=(%S+)")
      if r then
        if (line .. " "):find('message="creating instance" directory=' .. fg.cwd .. " ", 1, true) then
          local t = utc(ts)
          if t and math.abs(t - start) <= 3 then runs[r] = true end
        end
        sid[r] = line:match("session%.id=(ses_[%w]+)") or sid[r]
      end
    end
    if log then log:close() end
    for r in pairs(runs) do
      if run then return nil, "two opencode processes started together here; can't tell them apart" end
      run = r
    end
    local a = args(fg.pid)
    local id = (run and sid[run]) or a:match("%-%-session[=%s]+(ses_%w+)") or a:match("%-s%s+(ses_%w+)")
    if not id then return nil, "opencode hasn't opened a session yet" end
    local got = sh(string.format("sqlite3 \"$HOME/.local/share/opencode/opencode.db\" \"select title from session where id='%s'\"", id)):gsub("\n$", "")
    local want = title and title:match("^OC | (.+)$")
    if want and got ~= "" and got:sub(1, #want) ~= want and want:sub(1, #got) ~= got then
      return nil, "found session \"" .. got .. "\" but the pane shows \"" .. want .. "\""
    end
    return id, fg.cwd, got ~= "" and got or nil
  end,
  -- opencode keeps sessions in SQLite, so it moves with its own export and import.
  export = [[
d=$(mktemp -d) || exit 1
opencode export "$1" > "$d/session.json" && tar czf - -C "$d" session.json
rc=$?; rm -rf "$d"; exit $rc
]],
  -- import binds the session to the directory it runs in.
  import = [[
cd "$to" || fail "no directory $to"
opencode import "$t/session.json" >/dev/null || fail "opencode import failed"
resumed; exec opencode -s "$id"
]],
}

-- Pi runs under node, but sets its process title (and so argv0) to "pi".
local function is_pi(fg)
  return fg.name == "pi" or ((fg.argv0 or ""):match("([^/]*)$") == "pi")
end

-- Pi names a session's directory after its cwd: leading separator dropped, then
-- "/", "\" and ":" as "-", wrapped in "--".
local function pi_dir(cwd)
  return HOME .. "/.pi/agent/sessions/--" .. cwd:gsub("^[/\\]", ""):gsub("[/\\:]", "-") .. "--"
end

-- Pi titles its terminal "π - <session name> - <cwd basename>", or without the
-- name for an unnamed session. The session name, or nil.
function H.pi_name(title, cwd)
  local base = cwd:match("([^/]*)/*$")
  local rest = title and title:match("^%S+ %- (.*)$")
  local tail = " - " .. base
  if not rest or rest:sub(-#tail) ~= tail then return nil end
  local name = rest:sub(1, -#tail - 1)
  return name ~= "" and name or nil
end

H.pi = {
  bin = "pi",
  match = is_pi,
  -- Pi doesn't record which process has which session, so this infers it from the
  -- process's cwd (Pi keeps a session in the directory its cwd maps to), when the
  -- process started, and the terminal title, which carries the session's name:
  --  * Named: the sessions in this cwd with that name; if a fork shares it, only
  --    those written since this process started.
  --  * Unnamed: the sessions here with no name written since it started.
  -- If that leaves more than one, it won't guess.
  session = function(fg, title)
    local dir = pi_dir(fg.cwd)
    local want = H.pi_name(title, fg.cwd)
    local function list(script, ...)
      local out = {}
      for p in sh(script, ...):gmatch("[^\n]+") do out[#out + 1] = p end
      return out
    end
    -- Each session's latest name: grep -H lists a file's session_info entries in order.
    local names = {}
    for line in sh([[find "$1" -name '*.jsonl' -exec grep -H '"type":"session_info"' {} +]], dir):gmatch("[^\n]+") do
      local path, json = line:match("^(.-%.jsonl):(.*)$")
      local e = path and rex.json.decode(json)
      if e then names[path] = e.name end
    end
    local function header(path)
      local f = io.open(path)
      local first = f and f:read("*l")
      if f then f:close() end
      local hdr = first and rex.json.decode(first)
      return hdr and hdr.type == "session" and hdr.cwd == fg.cwd and hdr or nil
    end
    local function pick(paths)
      local out = {}
      for _, path in ipairs(paths) do
        if names[path] == want and header(path) then out[#out + 1] = path end
      end
      return out
    end
    local mins = tostring(math.ceil((age(fg.pid) or 0) / 60) + 1)
    local recent = list([[find "$1" -name '*.jsonl' -mmin -"$2"]], dir, mins)
    local found
    if want then
      local named = {}
      for path, name in pairs(names) do if name == want then named[#named + 1] = path end end
      found = pick(named)
      if #found > 1 then found = pick(recent) end
    else
      found = pick(recent)
    end
    if #found > 1 then return nil, "several pi sessions here could be this one; name it with /name to tell them apart" end
    if #found == 0 then
      return nil, want and ("no pi session here is named \"" .. want .. "\"")
        or "pi hasn't saved a session yet; send a message first"
    end
    return header(found[1]).id, fg.cwd, want
  end,
  -- A session is one JSONL file in the directory its cwd maps to. Its header
  -- records the cwd, so the import rewrites that to the target directory.
  export = [[
f=$(find "$HOME/.pi/agent/sessions" -name "*_$1.jsonl" | head -n 1)
test -n "$f" || { echo "no pi session $1" >&2; exit 1; }
cd "$(dirname "$f")" && tar czf - "$(basename "$f")"
]],
  import = [[
p="$HOME/.pi/agent/sessions/--$(printf %s "$to" | sed 's|^[/\\]||; s|[/\\:]|-|g')--"
mkdir -p "$p" || fail "couldn't make $p"
json=$(printf %s "$to" | sed 's/\\/\\\\/g; s/"/\\"/g')
for f in "$t"/*.jsonl; do
  CWD="$json" awk 'NR == 1 && match($0, /"cwd":"([^"\\]|\\.)*"/) {
    $0 = substr($0, 1, RSTART - 1) "\"cwd\":\"" ENVIRON["CWD"] "\"" substr($0, RSTART + RLENGTH)
  } { print }' "$f" > "$p/${f##*/}" || fail "couldn't copy the session into $p"
  s="$p/${f##*/}"
done
cd "$to" || fail "no directory $to"
resumed; exec pi --session "$s"
]],
}

H.order = { "claude", "codex", "opencode", "pi" }

-- The harness running in the foreground process, as name, harness.
function H.detect(fg)
  if not fg then return nil end
  for _, name in ipairs(H.order) do
    if H[name].match(fg) then return name, H[name] end
  end
end

return H
