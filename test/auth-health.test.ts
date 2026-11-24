import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
	clearAntigravityCredentials,
	inspectAntigravityAuth,
	removeConversation,
	resolveAntigravityAcpDirectory,
	resolveAntigravityAcpLaunch,
} from "../src/acp/antigravity.js";

const roots: string[] = [];
afterEach(() => {
	for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

function root(): string {
	const value = fs.mkdtempSync(path.join(os.tmpdir(), "antigravity-auth-"));
	roots.push(value);
	return value;
}

describe("Antigravity auth health", () => {
	it("does not mistake settings alone for completed authentication", () => {
		const directory = root();
		fs.writeFileSync(path.join(directory, "settings.json"), '{"auth":{"type":"oauth-personal"}}');
		expect(inspectAntigravityAuth(directory).status).toBe("configured-not-authenticated");
	});

	it("recognizes a structurally refreshable token and clears it", () => {
		const directory = root();
		fs.writeFileSync(path.join(directory, "settings.json"), '{"auth":{"type":"oauth-personal"}}');
		fs.writeFileSync(path.join(directory, "acp_token.json"), '{"refresh_token":"secret"}');
		expect(inspectAntigravityAuth(directory).status).toBe("oauth-refreshable");
		clearAntigravityCredentials(directory);
		expect(inspectAntigravityAuth(directory).status).toBe("missing");
	});

	it("reports corrupt token files", () => {
		const directory = root();
		fs.writeFileSync(path.join(directory, "acp_token.json"), "not-json");
		expect(inspectAntigravityAuth(directory).status).toBe("corrupt");
	});

	it("follows an explicit GEMINI_HOME to the relocated token", () => {
		const home = root();
		const acp = path.join(home, "antigravity-cli");
		fs.mkdirSync(acp, { recursive: true });
		fs.writeFileSync(path.join(acp, "acp_token.json"), '{"refresh_token":"secret"}');
		const previous = process.env.GEMINI_HOME;
		process.env.GEMINI_HOME = home;
		try {
			expect(resolveAntigravityAcpDirectory()).toBe(acp);
			expect(inspectAntigravityAuth().status).toBe("oauth-refreshable");
		} finally {
			if (previous === undefined) delete process.env.GEMINI_HOME;
			else process.env.GEMINI_HOME = previous;
		}
	});

	it("ignores an empty GEMINI_HOME and keeps the default home", () => {
		const previous = process.env.GEMINI_HOME;
		process.env.GEMINI_HOME = "  ";
		try {
			expect(resolveAntigravityAcpDirectory()).toBe(
				path.join(os.homedir(), ".gemini", "antigravity-cli"),
			);
		} finally {
			if (previous === undefined) delete process.env.GEMINI_HOME;
			else process.env.GEMINI_HOME = previous;
		}
	});

	it("resolves the store from the environment it is given", () => {
		expect(resolveAntigravityAcpDirectory({ HOME: "/child/home" })).toBe(
			path.join("/child/home", ".gemini", "antigravity-cli"),
		);
		expect(resolveAntigravityAcpDirectory({ HOME: "/child/home", GEMINI_HOME: "/child/workspace" })).toBe(
			path.join("/child/workspace", "antigravity-cli"),
		);
	});

	it("recognizes keychain credentials when no token file is present", () => {
		const directory = root();
		const health = inspectAntigravityAuth(directory, {}, () => true);
		expect(health).toMatchObject({
			status: "oauth-refreshable",
			authType: "oauth-personal",
			credentialStore: "keychain",
		});
	});

	it("launches agy CLI with acp, process-per-session, and optional yolo skip-permissions", () => {
		const dir = root();
		const agy = path.join(dir, "agy");
		fs.writeFileSync(agy, "binary", { mode: 0o755 });
		expect(resolveAntigravityAcpLaunch({ env: { AGY_ACP_BIN: agy } })).toEqual({
			command: agy,
			args: ["acp", "--process-per-session", "--disable-telemetry"],
			source: "env",
			kind: "agy-cli",
		});
		expect(resolveAntigravityAcpLaunch({ env: { AGY_ACP_BIN: agy }, dangerouslySkipPermissions: true })).toEqual({
			command: agy,
			args: ["acp", "--process-per-session", "--disable-telemetry", "--dangerously-skip-permissions"],
			source: "env",
			kind: "agy-cli",
		});
	});

	it("reads the API key from the inspected environment only", () => {
		const directory = root();
		fs.writeFileSync(path.join(directory, "acp_token.json"), '{"refresh_token":"secret"}');
		expect(inspectAntigravityAuth(directory, { GEMINI_API_KEY: "child-key" }).status).toBe("api-key-env");
		expect(inspectAntigravityAuth(directory, {}).status).toBe("oauth-refreshable");
	});
});

describe("removeConversation", () => {
	const sid = "0f8fad5b-d9cb-469f-a165-70867728950e";
	function conversations(names: string[]) {
		const directory = root();
		const dir = path.join(directory, "conversations");
		fs.mkdirSync(dir);
		for (const name of names) fs.writeFileSync(path.join(dir, name), "");
		return { directory, files: () => fs.readdirSync(dir).sort() };
	}

	it("removes exactly the four files of a UUID session", () => {
		const store = conversations([".db", ".db-shm", ".db-wal", ".meta", "-other.db"].map((suffix) => sid + suffix));
		removeConversation(sid, store.directory);
		expect(store.files()).toEqual([`${sid}-other.db`]);
	});

	it.each(["../x", "", `${sid.toUpperCase()}/x`, `../${sid}`])("ignores a session id that is not a UUID: %j", (id) => {
		const store = conversations([`${sid}.db`, "x.db"]);
		removeConversation(id, store.directory);
		expect(store.files()).toEqual([`${sid}.db`, "x.db"]);
	});

	it("skips a session path that is a directory without throwing", () => {
		const store = conversations([`${sid}.meta`]);
		fs.mkdirSync(path.join(store.directory, "conversations", `${sid}.db`));
		expect(() => removeConversation(sid, store.directory)).not.toThrow();
		expect(store.files()).toEqual([`${sid}.db`]);
	});
});
