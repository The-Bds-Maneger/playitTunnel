import { httpRequest } from "@the-bds-maneger/core-utils";
export class ApiClient {
  public api_base = "https://api.playit.cloud";
  public agent_secret?: string;
  public path: string
  async req<returnData = any>(type: string, data?: any) {
    return httpRequest.getJSON<returnData>({
      method: "POST",
      url: `${this.api_base}/${this.path}`,
      headers: {...(this.agent_secret?{Authorization: `agent-key ${this.agent_secret}`}:{})},
      body: {
        ...data,
        type
      }
    });
  }

  constructor(options: {api_base: string, agent_secret?: string} = {api_base: "https://api.playit.cloud"}) {
    this.api_base = options.api_base;
    this.agent_secret = options.agent_secret;
  }
};