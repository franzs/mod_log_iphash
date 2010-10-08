all: mod_log_iphash.la

mod_log_iphash.la: mod_log_iphash.c
	apxs -c -Wc,-Wall mod_log_iphash.c

install: mod_log_iphash.la
	apxs -i -a mod_log_iphash.la

clean:
	/bin/rm -f mod_log_iphash.la mod_log_iphash.lo mod_log_iphash.o mod_log_iphash.slo
