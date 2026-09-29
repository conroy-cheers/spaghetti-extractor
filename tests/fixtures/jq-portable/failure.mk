# Test-only source backend observation. Ordinary jq builds omit these objects.
FAILURE_WRAP = -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free,--wrap=strdup,--wrap=jv_string_slice,--wrap=jvp_dtoa_context_init
build/failure.o: diagnostics/failure.c diagnostics/allocation-observer.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Ibackends/jq/src -Idiagnostics -MMD -MP -c $< -o $@
build/allocation-observer.o: diagnostics/allocation-observer.c diagnostics/allocation-observer.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -DSPX_PORTABLE_ALLOCATION_OBSERVER -Idiagnostics -MMD -MP -c $< -o $@
failure: build/failure.o build/allocation-observer.o $(OBJECTS) backends/build/backend.stamp lifted-library
	$(CC) $(CFLAGS) $(LDFLAGS) $(FAILURE_WRAP) build/failure.o build/allocation-observer.o $(OBJECTS) -Wl,--start-group lifted/liblifted.a backends/build/.libs/libjq.a backends/build/vendor/oniguruma/src/.libs/libonig.a -Wl,--end-group -lm $(LDLIBS) -o $@
-include build/failure.d build/allocation-observer.d
