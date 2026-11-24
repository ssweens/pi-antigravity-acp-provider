import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { AntigravityAcpError } from "./errors.js";

export interface AntigravityLaunch {
	command: string;
	args: string[];
	source: "env" | "user-bin" | "managed" | "path";
	kind: "agy-cli" | "legacy-server";
}

export interface AntigravityLaunchOptions {
	dangerouslySkipPermissions?: boolean;
	env?: NodeJS.ProcessEnv;
}

const KEYCHAIN_SERVICE = "gemini";
const KEYCHAIN_ACCOUNT = "antigravity";
const SECURITY_CLI = "/usr/bin/security";
const VERSION_CACHE = new Map<string, string>();

function buildAgyCliLaunch(
	command: string,
	source: AntigravityLaunch["source"],
	options: AntigravityLaunchOptions,
): AntigravityLaunch {
	const args = ["acp", "--process-per-session", "--disable-telemetry"];
	if (options.dangerouslySkipPermissions) args.push("--dangerously-skip-permissions");
	return { command, args, source, kind: "agy-cli" };
}

function isLegacyServerCommand(command: string): boolean {
	const base = path.basename(command).toLowerCase();
	return base.startsWith("agy_acp_server");
}

export function resolveAntigravityAcpLaunch(options: AntigravityLaunchOptions = {}): AntigravityLaunch {
	const procEnv = options.env ?? process.env;
	const home = effectiveHome(procEnv);
	const env = procEnv.AGY_ACP_BIN?.trim();
	if (env) {
		const command = expandHome(env, home);
		if (executable(command)) {
			if (isLegacyServerCommand(command) || isScriptWrapper(command)) {
				return directOrWrapper(command, "env");
			}
			return buildAgyCliLaunch(command, "env", options);
		}
	}

	const agyNames = process.platform === "win32" ? ["agy.exe", "agy"] : ["agy"];
	for (const name of agyNames) {
		const userAgy = path.join(home, ".local", "bin", name);
		if (executable(userAgy)) return buildAgyCliLaunch(userAgy, "user-bin", options);
	}

	for (const directory of (procEnv.PATH ?? procEnv.Path ?? "").split(path.delimiter)) {
		if (!directory) continue;
		for (const name of agyNames) {
			const candidate = path.join(directory, name);
			if (executable(candidate)) return buildAgyCliLaunch(candidate, "path", options);
		}
	}

	throw new AntigravityAcpError(
		"spawn",
		"Google Antigravity CLI (agy) is not installed. Install agy (https://antigravity.google/docs/install?tab=cli) or set AGY_ACP_BIN.",
	);
}

/** Reads `agy --version` (cached per executable path). Never throws. */
export function readAgyCliVersion(command: string): string | undefined {
	const cached = VERSION_CACHE.get(command);
	if (cached) return cached;
	try {
		const raw = execFileSync(command, ["--version"], {
			encoding: "utf8",
			timeout: 5_000,
			stdio: ["ignore", "pipe", "ignore"],
		}).trim();
		const match = /\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?/u.exec(raw);
		const version = match?.[0] ?? (raw || undefined);
		if (version) VERSION_CACHE.set(command, version);
		return version;
	} catch {
		return undefined;
	}
}

export type AntigravityAuthStatus =
	| "api-key-env"
	| "oauth-refreshable"
	| "configured-not-authenticated"
	| "corrupt"
	| "missing";

export interface AntigravityAuthHealth {
	status: AntigravityAuthStatus;
	authType?: string;
	credentialStore?: "keychain" | "file";
	tokenFile: boolean;
	settingsFile: boolean;
}

/** Resolves `<home>/antigravity-cli` for the given environment: `<home>` is
 * `$GEMINI_HOME` when set and non-empty, otherwise `<HOME>/.gemini`. */
export function resolveAntigravityAcpDirectory(env: NodeJS.ProcessEnv = process.env): string {
	const home = effectiveHome(env);
	const geminiHome = env.GEMINI_HOME?.trim();
	const base = geminiHome ? expandHome(geminiHome, home) : path.join(home, ".gemini");
	return path.join(base, "antigravity-cli");
}

/** Checks macOS Keychain entry presence for `agy` CLI (`gemini`/`antigravity`).
 * Calling `find-generic-password` without `-w`/`-g` checks metadata only and
 * never triggers a Keychain access prompt. */
export function hasAgyKeychainCredential(): boolean {
	if (process.platform !== "darwin" || process.env.VITEST) return false;
	try {
		execFileSync(SECURITY_CLI, ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT], {
			stdio: "ignore",
			timeout: 3_000,
		});
		return true;
	} catch {
		return false;
	}
}

export function clearAgyKeychainCredentials(): void {
	if (process.platform !== "darwin" || process.env.VITEST) return;
	try {
		execFileSync(SECURITY_CLI, ["delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT], {
			stdio: "ignore",
			timeout: 3_000,
		});
	} catch {
		// Absent entry is already logged out.
	}
}

const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

/** Best-effort removal of the conversation store agy writes for one session:
 * `conversations/<id>.db`, `.db-shm`, `.db-wal` and `.meta`. Only for a session
 * this provider created and whose process has exited; any id that is not a
 * strict UUID is ignored so the path can never leave that directory. */
export function removeConversation(sessionId: string, directory = resolveAntigravityAcpDirectory()): void {
	if (!SESSION_ID.test(sessionId)) return;
	for (const suffix of [".db", ".db-shm", ".db-wal", ".meta"]) {
		try {
			fs.rmSync(path.join(directory, "conversations", sessionId + suffix), { force: true });
		} catch {
			// Best effort: a locked or unexpected entry stays in place.
		}
	}
}

/** Structural local health only. A network probe is required to call an OAuth
 * token valid; secret values are never returned or logged. `env` is the
 * environment whose credentials are inspected, not necessarily this process's. */
export function inspectAntigravityAuth(
	directory = resolveAntigravityAcpDirectory(),
	env: NodeJS.ProcessEnv = process.env,
	keychain: () => boolean = hasAgyKeychainCredential,
): AntigravityAuthHealth {
	const tokenPath = path.join(directory, "acp_token.json");
	const settingsPath = path.join(directory, "settings.json");
	const tokenFile = regularFile(tokenPath);
	const settingsFile = regularFile(settingsPath);
	let authType: string | undefined;
	if (settingsFile) {
		try {
			const settings = JSON.parse(fs.readFileSync(settingsPath, "utf8")) as {
				auth?: { type?: unknown };
			};
			if (typeof settings.auth?.type === "string") authType = settings.auth.type;
		} catch {
			return { status: "corrupt", tokenFile, settingsFile };
		}
	}
	if (env.GEMINI_API_KEY) return { status: "api-key-env", authType: "gemini-api-key", tokenFile, settingsFile };
	if (tokenFile) {
		try {
			const token = JSON.parse(fs.readFileSync(tokenPath, "utf8")) as { refresh_token?: unknown };
			if (typeof token.refresh_token === "string" && token.refresh_token.length > 0) {
				return {
					status: "oauth-refreshable",
					authType: authType ?? "oauth-personal",
					credentialStore: "file",
					tokenFile,
					settingsFile,
				};
			}
			return { status: "corrupt", ...(authType ? { authType } : {}), tokenFile, settingsFile };
		} catch {
			return { status: "corrupt", ...(authType ? { authType } : {}), tokenFile, settingsFile };
		}
	}
	if (keychain()) {
		return {
			status: "oauth-refreshable",
			authType: authType ?? "oauth-personal",
			credentialStore: "keychain",
			tokenFile,
			settingsFile,
		};
	}
	if (authType) return { status: "configured-not-authenticated", authType, tokenFile, settingsFile };
	return { status: "missing", tokenFile, settingsFile };
}

export function hasAntigravityAuth(): boolean {
	const status = inspectAntigravityAuth().status;
	return status === "api-key-env" || status === "oauth-refreshable";
}

/** Local logout fallback. Clears keychain entry (macOS) and local token/auth files. */
export function clearAntigravityCredentials(
	directory = resolveAntigravityAcpDirectory(),
): void {
	clearAgyKeychainCredentials();
	fs.rmSync(path.join(directory, "acp_token.json"), { force: true });
	const settingsPath = path.join(directory, "settings.json");
	try {
		const settings = JSON.parse(fs.readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
		delete settings.auth;
		const temporary = `${settingsPath}.${process.pid}.tmp`;
		fs.writeFileSync(temporary, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o600 });
		fs.renameSync(temporary, settingsPath);
	} catch {
		fs.rmSync(settingsPath, { force: true });
	}
}

function isScriptWrapper(command: string): boolean {
	try {
		const fd = fs.openSync(command, "r");
		const bytes = Buffer.alloc(64);
		const count = fs.readSync(fd, bytes, 0, bytes.length, 0);
		fs.closeSync(fd);
		return bytes.subarray(0, count).toString("utf8").startsWith("#!");
	} catch {
		return false;
	}
}

function directOrWrapper(command: string, source: AntigravityLaunch["source"]): AntigravityLaunch {
	if (isScriptWrapper(command)) {
		return { command, args: [], source, kind: "legacy-server" };
	}
	return { command, args: process.platform === "linux" ? ["--uid="] : [], source, kind: "legacy-server" };
}

function executable(file: string): boolean {
	try {
		fs.accessSync(file, fs.constants.X_OK);
		return fs.statSync(file).isFile();
	} catch {
		return false;
	}
}

function regularFile(file: string): boolean {
	try {
		return fs.statSync(file).isFile();
	} catch {
		return false;
	}
}

/** The home directory a child resolves `~` and the default store against. */
function effectiveHome(env: NodeJS.ProcessEnv): string {
	return env.HOME?.trim() || os.homedir();
}

function expandHome(file: string, home = os.homedir()): string {
	return file === "~" || file.startsWith("~/") ? path.join(home, file.slice(1)) : file;
}
