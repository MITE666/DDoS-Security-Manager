#pragma once

constexpr int PORT = 12345;
constexpr int PROXY_PORT = 54321;
constexpr int MAX_PACKET = 65535;
constexpr size_t LEAK_SIZE = 64 * 1024;
constexpr const char* CONN_LOG_PATH = "/app/logs/conn_activity.log";
constexpr const char* BANNED_IPS_PATH = "/app/logs/banned_ips.txt";