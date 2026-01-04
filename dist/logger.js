"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const winston_1 = __importDefault(require("winston"));
const { combine, timestamp, printf, colorize } = winston_1.default.format;
// Custom format for structured logging
const logFormat = printf(({ level, message, timestamp, ...metadata }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(metadata).length > 0) {
        msg += ` ${JSON.stringify(metadata)}`;
    }
    return msg;
});
// Create logger instance
exports.logger = winston_1.default.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: combine(timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }), logFormat),
    transports: [
        new winston_1.default.transports.Console({
            format: combine(colorize(), timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }), logFormat),
        }),
    ],
});
// Add file transport in production
if (process.env.NODE_ENV === 'production') {
    exports.logger.add(new winston_1.default.transports.File({
        filename: 'error.log',
        level: 'error',
    }));
    exports.logger.add(new winston_1.default.transports.File({
        filename: 'combined.log',
    }));
}
exports.default = exports.logger;
//# sourceMappingURL=logger.js.map