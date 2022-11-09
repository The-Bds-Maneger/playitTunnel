import { playit } from "./index";
const agent = new playit({secretKey: process.env.PLAYIT_SKEY||""});
agent.on("error", err => console.log(err));
agent.on("agentConfig", console.log);
agent.on("ping", ping => console.log("Ping: %fms", ping));