# Explicit diagnostic overlay: make -f Makefile -f diagnostics/allocation-fault.mk
# Use a clean build when changing configuration. Ordinary builds omit this object.
OBJECTS += build/allocation-fault.o
LDFLAGS += -Wl,--wrap=malloc -Wl,--wrap=main
hello hello-utf8: build/allocation-fault.o
build/allocation-fault.o: diagnostics/fault-portable.c diagnostics/allocation-fault.h application/services.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -Iapplication -Idiagnostics -MMD -MP -c $< -o $@
-include build/allocation-fault.d
