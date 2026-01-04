import { z } from 'zod';
declare const configSchema: any;
export type GatewayConfig = z.infer<typeof configSchema>;
export declare function loadConfig(): GatewayConfig;
export {};
//# sourceMappingURL=config.d.ts.map