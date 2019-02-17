#pragma once

#include <iostream>

namespace logger {

	static FILE *log_file = nullptr;

	template<class... ARGS>
	static inline void log(
		const char *message,
		const ARGS... args
	) {
		if (!log_file) return;
		fprintf(log_file, message, args...);
		fputc('\n', log_file);
		fflush(log_file);
	}

	static inline bool init() {
		return (log_file ? false : log_file = fopen(KL_LOG_FILE, "wt"));
	}

	static inline void free() {
		if (log_file) {
			fclose(log_file);
			log_file = nullptr;
		}
	}

}
