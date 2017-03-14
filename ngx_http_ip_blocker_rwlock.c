// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_ip_blocker_shm.h"

#include <assert.h>          // For assert
#include <semaphore.h>       // For sem_*

// rlock locks rw for reading.
ngx_int_t ngx_ip_blocker_rwlock_rlock(ngx_ip_blocker_rwlock_st *rw)
{
	if (ngx_atomic_fetch_add(&rw->reader_count, 1) < -1) {
		// A writer is pending, wait for it.
		if (sem_wait(&rw->reader_sem) != 0) {
			return NGX_ERROR;
		}
	}

	return NGX_OK;
}

// runlock undoes a single rlock call;
// it does not affect other simultaneous readers.
// It is a run-time error if rw is not locked for reading
// on entry to runlock.
ngx_int_t ngx_ip_blocker_rwlock_runlock(ngx_ip_blocker_rwlock_st *rw)
{
	int32_t r;

	r = ngx_atomic_fetch_add(&rw->reader_count, -1);
	if (r < 1) {
		assert(r != 0 && r != -NGX_IP_BLOCKER_MAX_READERS);

		// A writer is pending.
		if (ngx_atomic_fetch_add(&rw->reader_wait, -1) == 1) {
			// The last reader unblocks the writer.
			if (sem_post(&rw->writer_sem) != 0) {
				return NGX_ERROR;
			}
		}
	}

	return NGX_OK;
}
