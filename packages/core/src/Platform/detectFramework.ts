// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Framework } from './types';
import { detect } from './detection';

// We want to cache detection since the framework won't change
let frameworkCache: Framework | undefined;

// Setup the detection reset tracking / timeout delays
let resetTriggered = false;
const SSR_RESET_TIMEOUT = 10; // ms
const WEB_RESET_TIMEOUT = 10; // ms

export const detectFramework = (): Framework => {
	if (!frameworkCache) {
		frameworkCache = detect();

		// Retry once for either Unknown type after a delay (explained below)
		resetTimeout(Framework.ServerSideUnknown, SSR_RESET_TIMEOUT);
		resetTimeout(Framework.WebUnknown, WEB_RESET_TIMEOUT);
	}
	return frameworkCache;
};

export function clearCache() {
	frameworkCache = undefined;
}

// For a framework type and a delay amount, setup the event to re-detect
//   During the runtime boot, it is possible that framework detection will
//   be triggered before the framework has made modifications to the
//   global/window/etc needed for detection. When no framework is detected
//   we will reset and try again to ensure we don't use a cached
//   non-framework detection result for all requests.
function resetTimeout(framework: Framework, delay: number) {
	if (frameworkCache === framework && !resetTriggered) {
		setTimeout(() => {
			clearCache();
			resetTriggered = true;
		}, delay);
	}
}
