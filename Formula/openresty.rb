require 'etc'

class Openresty < Formula
  desc "Scalable Web Platform by Extending NGINX with Lua"
  homepage "https://openresty.org"
  VERSION = "1.21.4.1".freeze
  revision 1
  url "https://openresty.org/download/openresty-#{VERSION}.tar.gz"
  sha256 "0c5093b64f7821e85065c99e5d4e6cc31820cfd7f37b9a0dec84209d87a2af99"

  option "with-postgresql", "Compile with ngx_http_postgres_module"
  option "with-iconv", "Compile with ngx_http_iconv_module"
  option "with-slice", "Compile with ngx_http_slice_module"

  depends_on "geoip"
  depends_on "openresty/brew/openresty-openssl111"
  depends_on "pcre"
  depends_on "postgresql" => :optional

  skip_clean "site"
  skip_clean "pod"
  skip_clean "nginx"
  skip_clean "luajit"

  stable do
    # Patch with https://github.com/openresty/lua-nginx-module/pull/2037
    # And https://github.com/openresty/lua-resty-core/pull/391
    # TODO: https://github.com/openresty/stream-lua-nginx-module/pull/293
  
    patch :DATA
  end

  def install
    # Configure
    cc_opt = "-I#{HOMEBREW_PREFIX}/include -I#{Formula["pcre"].opt_include} -I#{Formula["openresty/brew/openresty-openssl111"].opt_include}"
    ld_opt = "-L#{HOMEBREW_PREFIX}/lib -L#{Formula["pcre"].opt_lib} -L#{Formula["openresty/brew/openresty-openssl111"].opt_lib}"

    args = %W[
      -j#{Etc.nprocessors}
      --prefix=#{prefix}
      --pid-path=#{var}/run/openresty.pid
      --lock-path=#{var}/run/openresty.lock
      --conf-path=#{etc}/openresty/nginx.conf
      --http-log-path=#{var}/log/nginx/access.log
      --error-log-path=#{var}/log/nginx/error.log
      --with-cc-opt=#{cc_opt}
      --with-ld-opt=#{ld_opt}
      --with-pcre-jit
      --without-http_rds_json_module
      --without-http_rds_csv_module
      --without-lua_rds_parser
      --with-ipv6
      --with-stream
      --with-stream_ssl_module
      --with-stream_ssl_preread_module
      --with-http_v2_module
      --without-mail_pop3_module
      --without-mail_imap_module
      --without-mail_smtp_module
      --with-http_stub_status_module
      --with-http_realip_module
      --with-http_addition_module
      --with-http_auth_request_module
      --with-http_secure_link_module
      --with-http_random_index_module
      --with-http_geoip_module
      --with-http_gzip_static_module
      --with-http_sub_module
      --with-http_dav_module
      --with-http_flv_module
      --with-http_mp4_module
      --with-http_gunzip_module
      --with-threads
      --with-luajit-xcflags=-DLUAJIT_NUMMODE=2\ -DLUAJIT_ENABLE_LUA52COMPAT\ -fno-stack-check
    ]

    args << "--with-http_postgres_module" if build.with? "postgresql"
    args << "--with-http_iconv_module" if build.with? "iconv"
    args << "--with-http_slice_module" if build.with? "slice"

    system "./configure", *args

    # Install
    system "make"
    system "make", "install"
  end

  plist_options :manual => "openresty"

  def plist
    <<~EOS
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
        <dict>
          <key>Label</key>
          <string>#{plist_name}</string>
          <key>RunAtLoad</key>
          <true/>
          <key>KeepAlive</key>
          <false/>
          <key>ProgramArguments</key>
          <array>
            <string>#{opt_prefix}/bin/openresty</string>
            <string>-g</string>
            <string>daemon off;</string>
          </array>
          <key>WorkingDirectory</key>
          <string>#{HOMEBREW_PREFIX}</string>
        </dict>
      </plist>
    EOS
  end

  def caveats
    <<~EOS
      You can find the configuration files for openresty under #{etc}/openresty/.
    EOS
  end

  test do
    system "#{bin}/openresty", "-V"
  end
end

__END__
diff --color -Naur openresty-1.21.4.1/bundle/lua-resty-core-0.1.23/lib/resty/core/response.lua openresty-1.21.4.1.patched/bundle/lua-resty-core-0.1.23/lib/resty/core/response.lua
--- openresty-1.21.4.1/bundle/lua-resty-core-0.1.23/lib/resty/core/response.lua	2021-11-14 09:43:51
+++ openresty-1.21.4.1.patched/bundle/lua-resty-core-0.1.23/lib/resty/core/response.lua	2022-11-25 21:17:08
@@ -45,6 +45,61 @@
 ]]


+local ngx_lua_ffi_set_resp_header
+
+local MACOS = jit and jit.os == "OSX"
+
+if MACOS then
+    ffi.cdef[[
+        typedef struct {
+            ngx_http_request_t   *r;
+            const char           *key_data;
+            size_t                key_len;
+            int                   is_nil;
+            const char           *sval;
+            size_t                sval_len;
+            void                 *mvals;
+            size_t                mvals_len;
+            int                   override;
+            char                **errmsg;
+        } ngx_http_lua_set_resp_header_params_t;
+
+        int ngx_http_lua_ffi_set_resp_header_macos(
+            ngx_http_lua_set_resp_header_params_t *p);
+    ]]
+
+    local set_params = ffi.new("ngx_http_lua_set_resp_header_params_t")
+
+    ngx_lua_ffi_set_resp_header = function(r, key, key_len, is_nil,
+                                           sval, sval_len, mvals,
+                                           mvals_len, override, err)
+
+        set_params.r = r
+        set_params.key_data = key
+        set_params.key_len = key_len
+        set_params.is_nil = is_nil
+        set_params.sval = sval
+        set_params.sval_len = sval_len
+        set_params.mvals = mvals
+        set_params.mvals_len = mvals_len
+        set_params.override = override
+        set_params.errmsg = err
+
+        return C.ngx_http_lua_ffi_set_resp_header_macos(set_params)
+    end
+
+else
+    ngx_lua_ffi_set_resp_header = function(r, key, key_len, is_nil,
+                                           sval, sval_len, mvals,
+                                           mvals_len, override, err)
+
+        return C.ngx_http_lua_ffi_set_resp_header(r, key, key_len, is_nil,
+                                                  sval, sval_len, mvals,
+                                                  mvals_len, override, err)
+    end
+end
+
+
 local function set_resp_header(tb, key, value, no_override)
     local r = get_request()
     if not r then
@@ -61,8 +116,8 @@
             error("invalid header value", 3)
         end

-        rc = C.ngx_http_lua_ffi_set_resp_header(r, key, #key, true, nil, 0, nil,
-                                                0, 1, errmsg)
+        rc = ngx_lua_ffi_set_resp_header(r, key, #key, true, nil, 0, nil,
+                                         0, 1, errmsg)
     else
         local sval, sval_len, mvals, mvals_len, buf

@@ -99,9 +154,9 @@
         end

         local override_int = no_override and 0 or 1
-        rc = C.ngx_http_lua_ffi_set_resp_header(r, key, #key, false, sval,
-                                                sval_len, mvals, mvals_len,
-                                                override_int, errmsg)
+        rc = ngx_lua_ffi_set_resp_header(r, key, #key, false, sval,
+                                         sval_len, mvals, mvals_len,
+                                         override_int, errmsg)
     end

     if rc == 0 or rc == FFI_DECLINED then
diff --color -Naur openresty-1.21.4.1/bundle/lua-resty-core-0.1.23/lib/resty/core/shdict.lua openresty-1.21.4.1.patched/bundle/lua-resty-core-0.1.23/lib/resty/core/shdict.lua
--- openresty-1.21.4.1/bundle/lua-resty-core-0.1.23/lib/resty/core/shdict.lua	2021-11-14 09:43:51
+++ openresty-1.21.4.1.patched/bundle/lua-resty-core-0.1.23/lib/resty/core/shdict.lua	2022-11-25 21:17:08
@@ -72,9 +72,39 @@
 void *ngx_http_lua_ffi_shdict_udata_to_zone(void *zone_udata);
     ]]

-    ngx_lua_ffi_shdict_get = C.ngx_http_lua_ffi_shdict_get
-    ngx_lua_ffi_shdict_incr = C.ngx_http_lua_ffi_shdict_incr
-    ngx_lua_ffi_shdict_store = C.ngx_http_lua_ffi_shdict_store
+    ngx_lua_ffi_shdict_get = function(zone, key, key_len, value_type,
+                                      str_value_buf, value_len,
+                                      num_value, user_flags,
+                                      get_stale, is_stale, errmsg)
+
+        return C.ngx_http_lua_ffi_shdict_get(zone, key, key_len, value_type,
+                                             str_value_buf, value_len,
+                                             num_value, user_flags,
+                                             get_stale, is_stale, errmsg)
+    end
+
+    ngx_lua_ffi_shdict_incr = function(zone, key,
+                                       key_len, value, err, has_init,
+                                       init, init_ttl, forcible)
+
+        return C.ngx_http_lua_ffi_shdict_incr(zone, key,
+                                              key_len, value, err, has_init,
+                                              init, init_ttl, forcible)
+    end
+
+    ngx_lua_ffi_shdict_store = function(zone, op,
+                                        key, key_len, value_type,
+                                        str_value_buf, str_value_len,
+                                        num_value, exptime, user_flags,
+                                        errmsg, forcible)
+
+        return C.ngx_http_lua_ffi_shdict_store(zone, op,
+                                               key, key_len, value_type,
+                                               str_value_buf, str_value_len,
+                                               num_value, exptime, user_flags,
+                                               errmsg, forcible)
+    end
+
     ngx_lua_ffi_shdict_flush_all = C.ngx_http_lua_ffi_shdict_flush_all
     ngx_lua_ffi_shdict_get_ttl = C.ngx_http_lua_ffi_shdict_get_ttl
     ngx_lua_ffi_shdict_set_expire = C.ngx_http_lua_ffi_shdict_set_expire
@@ -126,9 +156,39 @@
 void *ngx_stream_lua_ffi_shdict_udata_to_zone(void *zone_udata);
     ]]

-    ngx_lua_ffi_shdict_get = C.ngx_stream_lua_ffi_shdict_get
-    ngx_lua_ffi_shdict_incr = C.ngx_stream_lua_ffi_shdict_incr
-    ngx_lua_ffi_shdict_store = C.ngx_stream_lua_ffi_shdict_store
+    ngx_lua_ffi_shdict_get = function(zone, key, key_len, value_type,
+                                      str_value_buf, value_len,
+                                      num_value, user_flags,
+                                      get_stale, is_stale, errmsg)
+
+        return C.ngx_stream_lua_ffi_shdict_get(zone, key, key_len, value_type,
+                                               str_value_buf, value_len,
+                                               num_value, user_flags,
+                                               get_stale, is_stale, errmsg)
+    end
+
+    ngx_lua_ffi_shdict_incr = function(zone, key,
+                                       key_len, value, err, has_init,
+                                       init, init_ttl, forcible)
+
+        return C.ngx_stream_lua_ffi_shdict_incr(zone, key,
+                                                key_len, value, err, has_init,
+                                                init, init_ttl, forcible)
+    end
+
+    ngx_lua_ffi_shdict_store = function(zone, op,
+                                        key, key_len, value_type,
+                                        str_value_buf, str_value_len,
+                                        num_value, exptime, user_flags,
+                                        errmsg, forcible)
+
+        return C.ngx_stream_lua_ffi_shdict_store(zone, op,
+                                                 key, key_len, value_type,
+                                                 str_value_buf, str_value_len,
+                                                 num_value, exptime, user_flags,
+                                                 errmsg, forcible)
+    end
+
     ngx_lua_ffi_shdict_flush_all = C.ngx_stream_lua_ffi_shdict_flush_all
     ngx_lua_ffi_shdict_get_ttl = C.ngx_stream_lua_ffi_shdict_get_ttl
     ngx_lua_ffi_shdict_set_expire = C.ngx_stream_lua_ffi_shdict_set_expire
@@ -152,6 +212,240 @@
 else
     error("unknown subsystem: " .. subsystem)
 end
+
+
+local MACOS = jit and jit.os == "OSX"
+
+if MACOS and subsystem == 'http' then
+    ffi.cdef[[
+typedef struct {
+    void                  *zone;
+    const unsigned char   *key;
+    size_t                 key_len;
+    int                   *value_type;
+    unsigned char        **str_value_buf;
+    size_t                *str_value_len;
+    double                *num_value;
+    int                   *user_flags;
+    int                    get_stale;
+    int                   *is_stale;
+    char                 **errmsg;
+} ngx_http_lua_shdict_get_params_t;
+
+typedef struct {
+    void                  *zone;
+    int                    op;
+    const unsigned char   *key;
+    size_t                 key_len;
+    int                    value_type;
+    const unsigned char   *str_value_buf;
+    size_t                 str_value_len;
+    double                 num_value;
+    long                   exptime;
+    int                    user_flags;
+    char                 **errmsg;
+    int                   *forcible;
+} ngx_http_lua_shdict_store_params_t;
+
+typedef struct {
+    void                  *zone;
+    const unsigned char   *key;
+    size_t                 key_len;
+    double                *num_value;
+    char                 **errmsg;
+    int                    has_init;
+    double                 init;
+    long                   init_ttl;
+    int                   *forcible;
+} ngx_http_lua_shdict_incr_params_t;
+
+int ngx_http_lua_ffi_shdict_get_macos(
+        ngx_http_lua_shdict_get_params_t *p);
+int ngx_http_lua_ffi_shdict_store_macos(
+        ngx_http_lua_shdict_store_params_t *p);
+int ngx_http_lua_ffi_shdict_incr_macos(
+        ngx_http_lua_shdict_incr_params_t *p);
+    ]]
+
+    local get_params = ffi_new("ngx_http_lua_shdict_get_params_t")
+    local incr_params = ffi_new("ngx_http_lua_shdict_incr_params_t")
+    local store_params = ffi_new("ngx_http_lua_shdict_store_params_t")
+
+    ngx_lua_ffi_shdict_get = function(zone, key, key_len, value_type,
+                                      str_value_buf, value_len,
+                                      num_value, user_flags,
+                                      get_stale, is_stale, errmsg)
+
+        get_params.zone = zone
+        get_params.key = key
+        get_params.key_len = key_len
+        get_params.value_type = value_type
+        get_params.str_value_buf = str_value_buf
+        get_params.str_value_len = value_len
+        get_params.num_value = num_value
+        get_params.user_flags = user_flags
+        get_params.get_stale = get_stale
+        get_params.is_stale = is_stale
+        get_params.errmsg = errmsg
+
+        return C.ngx_http_lua_ffi_shdict_get_macos(get_params)
+    end
+
+    ngx_lua_ffi_shdict_incr = function(zone, key,
+                                       key_len, value, err, has_init,
+                                       init, init_ttl, forcible)
+
+        incr_params.zone = zone
+        incr_params.key = key
+        incr_params.key_len = key_len
+        incr_params.num_value = value
+        incr_params.errmsg = err
+        incr_params.has_init = has_init
+        incr_params.init = init
+        incr_params.init_ttl = init_ttl
+        incr_params.forcible = forcible
+
+        return C.ngx_http_lua_ffi_shdict_incr_macos(incr_params)
+    end
+
+    ngx_lua_ffi_shdict_store = function(zone, op,
+                                        key, key_len, value_type,
+                                        str_value_buf, str_value_len,
+                                        num_value, exptime, user_flags,
+                                        errmsg, forcible)
+
+        store_params.zone = zone
+        store_params.op = op
+        store_params.key = key
+        store_params.key_len = key_len
+        store_params.value_type = value_type
+        store_params.str_value_buf = str_value_buf
+        store_params.str_value_len = str_value_len
+        store_params.num_value = num_value
+        store_params.exptime = exptime
+        store_params.user_flags = user_flags
+        store_params.errmsg = errmsg
+        store_params.forcible = forcible
+
+        return C.ngx_http_lua_ffi_shdict_store_macos(store_params)
+    end
+end
+
+if MACOS and subsystem == 'stream' then
+    ffi.cdef[[
+typedef struct {
+    void                  *zone;
+    const unsigned char   *key;
+    size_t                 key_len;
+    int                   *value_type;
+    unsigned char        **str_value_buf;
+    size_t                *str_value_len;
+    double                *num_value;
+    int                   *user_flags;
+    int                    get_stale;
+    int                   *is_stale;
+    char                 **errmsg;
+} ngx_stream_lua_shdict_get_params_t;
+
+typedef struct {
+    void                  *zone;
+    int                    op;
+    const unsigned char   *key;
+    size_t                 key_len;
+    int                    value_type;
+    const unsigned char   *str_value_buf;
+    size_t                 str_value_len;
+    double                 num_value;
+    long                   exptime;
+    int                    user_flags;
+    char                 **errmsg;
+    int                   *forcible;
+} ngx_stream_lua_shdict_store_params_t;
+
+typedef struct {
+    void                  *zone;
+    const unsigned char   *key;
+    size_t                 key_len;
+    double                *num_value;
+    char                 **errmsg;
+    int                    has_init;
+    double                 init;
+    long                   init_ttl;
+    int                   *forcible;
+} ngx_stream_lua_shdict_incr_params_t;
+
+int ngx_stream_lua_ffi_shdict_get_macos(
+        ngx_stream_lua_shdict_get_params_t *p);
+int ngx_stream_lua_ffi_shdict_store_macos(
+        ngx_stream_lua_shdict_store_params_t *p);
+int ngx_stream_lua_ffi_shdict_incr_macos(
+        ngx_stream_lua_shdict_incr_params_t *p);
+    ]]
+
+    local get_params = ffi_new("ngx_stream_lua_shdict_get_params_t")
+    local store_params = ffi_new("ngx_stream_lua_shdict_store_params_t")
+    local incr_params = ffi_new("ngx_stream_lua_shdict_incr_params_t")
+
+    ngx_lua_ffi_shdict_get = function(zone, key, key_len, value_type,
+                                      str_value_buf, value_len,
+                                      num_value, user_flags,
+                                      get_stale, is_stale, errmsg)
+
+        get_params.zone = zone
+        get_params.key = key
+        get_params.key_len = key_len
+        get_params.value_type = value_type
+        get_params.str_value_buf = str_value_buf
+        get_params.str_value_len = value_len
+        get_params.num_value = num_value
+        get_params.user_flags = user_flags
+        get_params.get_stale = get_stale
+        get_params.is_stale = is_stale
+        get_params.errmsg = errmsg
+
+        return C.ngx_stream_lua_ffi_shdict_get_macos(get_params)
+    end
+
+    ngx_lua_ffi_shdict_incr = function(zone, key,
+                                       key_len, value, err, has_init,
+                                       init, init_ttl, forcible)
+
+        incr_params.zone = zone
+        incr_params.key = key
+        incr_params.key_len = key_len
+        incr_params.num_value = value
+        incr_params.errmsg = err
+        incr_params.has_init = has_init
+        incr_params.init = init
+        incr_params.init_ttl = init_ttl
+        incr_params.forcible = forcible
+
+        return C.ngx_stream_lua_ffi_shdict_incr_macos(incr_params)
+    end
+
+    ngx_lua_ffi_shdict_store = function(zone, op,
+                                        key, key_len, value_type,
+                                        str_value_buf, str_value_len,
+                                        num_value, exptime, user_flags,
+                                        errmsg, forcible)
+
+        store_params.zone = zone
+        store_params.op = op
+        store_params.key = key
+        store_params.key_len = key_len
+        store_params.value_type = value_type
+        store_params.str_value_buf = str_value_buf
+        store_params.str_value_len = str_value_len
+        store_params.num_value = num_value
+        store_params.exptime = exptime
+        store_params.user_flags = user_flags
+        store_params.errmsg = errmsg
+        store_params.forcible = forcible
+
+        return C.ngx_stream_lua_ffi_shdict_store_macos(store_params)
+    end
+end
+

 if not pcall(function () return C.free end) then
     ffi.cdef[[
diff --color -Naur openresty-1.21.4.1/bundle/ngx_lua-0.10.21/src/ngx_http_lua_headers.c openresty-1.21.4.1.patched/bundle/ngx_lua-0.10.21/src/ngx_http_lua_headers.c
--- openresty-1.21.4.1/bundle/ngx_lua-0.10.21/src/ngx_http_lua_headers.c	2022-03-02 14:54:22
+++ openresty-1.21.4.1.patched/bundle/ngx_lua-0.10.21/src/ngx_http_lua_headers.c	2022-11-25 21:20:51
@@ -1211,4 +1211,16 @@
 #endif


+#if (NGX_DARWIN)
+int
+ngx_http_lua_ffi_set_resp_header_macos(ngx_http_lua_set_resp_header_params_t *p)
+{
+    return ngx_http_lua_ffi_set_resp_header(p->r, p->key_data, p->key_len,
+                                            p->is_nil, p->sval, p->sval_len,
+                                            p->mvals, p->mvals_len,
+                                            p->override, p->errmsg);
+}
+#endif
+
+
 /* vi:set ft=c ts=4 sw=4 et fdm=marker: */
diff --color -Naur openresty-1.21.4.1/bundle/ngx_lua-0.10.21/src/ngx_http_lua_headers_out.h openresty-1.21.4.1.patched/bundle/ngx_lua-0.10.21/src/ngx_http_lua_headers_out.h
--- openresty-1.21.4.1/bundle/ngx_lua-0.10.21/src/ngx_http_lua_headers_out.h	2022-03-02 14:54:22
+++ openresty-1.21.4.1.patched/bundle/ngx_lua-0.10.21/src/ngx_http_lua_headers_out.h	2022-11-25 21:20:51
@@ -12,6 +12,22 @@
 #include "ngx_http_lua_common.h"


+#if (NGX_DARWIN)
+typedef struct {
+    ngx_http_request_t   *r;
+    const char           *key_data;
+    size_t                key_len;
+    int                   is_nil;
+    const char           *sval;
+    size_t                sval_len;
+    void                 *mvals;
+    size_t                mvals_len;
+    int                   override;
+    char                **errmsg;
+} ngx_http_lua_set_resp_header_params_t;
+#endif
+
+
 ngx_int_t ngx_http_lua_set_output_header(ngx_http_request_t *r,
     ngx_http_lua_ctx_t *ctx, ngx_str_t key, ngx_str_t value, unsigned override);
 int ngx_http_lua_get_output_header(lua_State *L, ngx_http_request_t *r,
diff --color -Naur openresty-1.21.4.1/bundle/ngx_lua-0.10.21/src/ngx_http_lua_shdict.c openresty-1.21.4.1.patched/bundle/ngx_lua-0.10.21/src/ngx_http_lua_shdict.c
--- openresty-1.21.4.1/bundle/ngx_lua-0.10.21/src/ngx_http_lua_shdict.c	2022-03-02 14:54:22
+++ openresty-1.21.4.1.patched/bundle/ngx_lua-0.10.21/src/ngx_http_lua_shdict.c	2022-11-25 21:20:51
@@ -2092,4 +2092,38 @@
 #endif


+#if (NGX_DARWIN)
+int
+ngx_http_lua_ffi_shdict_get_macos(ngx_http_lua_shdict_get_params_t *p)
+{
+    return ngx_http_lua_ffi_shdict_get(p->zone, p->key, p->key_len,
+                                       p->value_type, p->str_value_buf,
+                                       p->str_value_len, p->num_value,
+                                       p->user_flags, p->get_stale,
+                                       p->is_stale, p->errmsg);
+}
+
+
+int
+ngx_http_lua_ffi_shdict_store_macos(ngx_http_lua_shdict_store_params_t *p)
+{
+    return ngx_http_lua_ffi_shdict_store(p->zone, p->op, p->key, p->key_len,
+                                         p->value_type, p->str_value_buf,
+                                         p->str_value_len, p->num_value,
+                                         p->exptime, p->user_flags,
+                                         p->errmsg, p->forcible);
+}
+
+
+int
+ngx_http_lua_ffi_shdict_incr_macos(ngx_http_lua_shdict_incr_params_t *p)
+{
+    return ngx_http_lua_ffi_shdict_incr(p->zone, p->key, p->key_len,
+                                        p->num_value, p->errmsg,
+                                        p->has_init, p->init, p->init_ttl,
+                                        p->forcible);
+}
+#endif
+
+
 /* vi:set ft=c ts=4 sw=4 et fdm=marker: */
diff --color -Naur openresty-1.21.4.1/bundle/ngx_lua-0.10.21/src/ngx_http_lua_shdict.h openresty-1.21.4.1.patched/bundle/ngx_lua-0.10.21/src/ngx_http_lua_shdict.h
--- openresty-1.21.4.1/bundle/ngx_lua-0.10.21/src/ngx_http_lua_shdict.h	2022-03-02 14:54:22
+++ openresty-1.21.4.1.patched/bundle/ngx_lua-0.10.21/src/ngx_http_lua_shdict.h	2022-11-25 21:20:51
@@ -55,6 +55,52 @@
 } ngx_http_lua_shm_zone_ctx_t;


+#if (NGX_DARWIN)
+typedef struct {
+    void                  *zone;
+    const unsigned char   *key;
+    size_t                 key_len;
+    int                   *value_type;
+    unsigned char        **str_value_buf;
+    size_t                *str_value_len;
+    double                *num_value;
+    int                   *user_flags;
+    int                    get_stale;
+    int                   *is_stale;
+    char                 **errmsg;
+} ngx_http_lua_shdict_get_params_t;
+
+
+typedef struct {
+    void                  *zone;
+    int                    op;
+    const unsigned char   *key;
+    size_t                 key_len;
+    int                    value_type;
+    const unsigned char   *str_value_buf;
+    size_t                 str_value_len;
+    double                 num_value;
+    long                   exptime;
+    int                    user_flags;
+    char                 **errmsg;
+    int                   *forcible;
+} ngx_http_lua_shdict_store_params_t;
+
+
+typedef struct {
+    void                  *zone;
+    const unsigned char   *key;
+    size_t                 key_len;
+    double                *num_value;
+    char                 **errmsg;
+    int                    has_init;
+    double                 init;
+    long                   init_ttl;
+    int                   *forcible;
+} ngx_http_lua_shdict_incr_params_t;
+#endif
+
+
 ngx_int_t ngx_http_lua_shdict_init_zone(ngx_shm_zone_t *shm_zone, void *data);
 void ngx_http_lua_shdict_rbtree_insert_value(ngx_rbtree_node_t *temp,
     ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
