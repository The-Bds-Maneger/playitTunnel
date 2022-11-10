import { playit } from "./index";
import { config } from "dotenv";
config();
const agent = new playit({secretKey: process.env.PLAYIT_SKEY||""});
agent.on("error", err => console.log(err));
agent.on("status", async status => {
  if (status !== "connected") return;
  console.log("Success to auth agent");
  // agent.on("ping", ping => console.log("Ping: %fms", ping));
  agent.on("agentConfig", config => console.log("Secret Key: '%s', Control Address: '%s'", config.secret_key, config.control_address));
  const tunnel = (await agent.listTunnels()).tunnels.at(-1);
  console.log("Tunnel name: '%s', id: '%s'", tunnel.name, tunnel.id);
  agent.connectTunnel(tunnel.id).then(console.log);
});