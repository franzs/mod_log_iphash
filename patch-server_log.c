--- server/log.c.orig	2009-05-21 19:31:52.000000000 +0200
+++ server/log.c	2010-10-06 12:18:34.000000000 +0200
@@ -633,7 +633,7 @@
          * first. -djg
          */
         len += apr_snprintf(errstr + len, MAX_STRING_LEN - len,
-                            "[client %s] ", c->remote_ip);
+                            "[client ANONYMIZED] ");
     }
     if (status != 0) {
         if (status < APR_OS_START_EAIERR) {
