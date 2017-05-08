#pragma once

int esper_socket;

int esper_connect(char *ip, int port);
void esper_disconnect();