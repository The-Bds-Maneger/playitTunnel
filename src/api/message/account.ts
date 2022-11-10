import { randomBytes } from "node:crypto";
import { ApiClient } from "../apiClient";
export type tunnelType = "minecraft-java"|"minecraft-bedrock"|"valheim"|"terraria"|"starbound"|"rust"|"7days"|"unturned";
export type tunnelList = {
  type: "account-tunnels",
  agent_id: string,
  tunnels: {
    id: string,
    enabled: boolean,
    name?: string,
    ip_address: string,
    ip_hostname: string,
    custom_domain?: {
      id: string,
      name: string,
      target: {type: "port-allocation", id: string}|{type: "ip-address", ip: string}
    },
    assigned_domain: string,
    display_address: string,
    is_dedicated_ip: boolean,
    from_port: number,
    to_port: number,
    tunnel_type: tunnelType,
    port_type: "udp"|"tcp"|"both",
    firewall_id?: string,
    protocol: {
      protocol: "to-agent",
      local_ip: string,
      local_port: number,
      agent_id: number
    }
  }[]
}

export default class account extends ApiClient {
  path = "account";

  async CreateTunnel(options: {tunnelType?: tunnelType, name: string, portType: "tcp"|"udp"|"both", local: {ip?: string, port: number, count?: number}}) {
    return this.req<{id: string}>("create-tunnel", {
      agent_id: null,

      // Tunnel to
      tunnel_type: options.tunnelType||null,
      name: options.name||randomBytes(8).toString("hex"),

      // Port config
      port_type: options.portType||"both",
      port_count: options?.local?.count||1,
      local_ip: options?.local?.ip||"0.0.0.0",
      local_port: options?.local?.port||null,
    }).then(res => res.id);
  }

  async ListAccountTunnels() {
    const data = await this.req<tunnelList>("list-account-tunnels");
    return {agent_id: data.agent_id, tunnels: data.tunnels};
  }
}