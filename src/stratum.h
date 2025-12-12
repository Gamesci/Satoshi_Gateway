#ifndef STRATUM_H
#define STRATUM_H
#include "bitcoin.h"

int stratum_start_thread();
void stratum_broadcast_job(Template *tmpl);

#endif
