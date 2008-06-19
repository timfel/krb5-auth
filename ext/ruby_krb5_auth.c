/*
 * ruby_krb5_auth.c: Ruby bindings for Kerberos authentication
 *
 * Copyright (C) 2008 Red Hat Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Chris Lalancette <clalance@redhat.com>
 */

#include <ruby.h>
#include <krb5.h>
#include <stdio.h>
#include <strings.h>

static VALUE mKerberos;
static VALUE cKrb5;
static VALUE cCred;
static VALUE cKrb5_Exception;

struct ruby_krb5 {
  krb5_context ctx;
  krb5_creds creds;
  krb5_principal princ;
};

#define OOM_EXCEPT() rb_raise(cKrb5_Exception, "%s", "Error mallocing memory");
#define NOSTRUCT_EXCEPT() rb_raise(cKrb5_Exception, "%s", "Class not initialized properly (try 'new')");

void Krb5_register_error(int error)
{
  rb_raise(cKrb5_Exception, "%s", error_message(error));
}

static void kerb_free(void *p)
{
  struct ruby_krb5 *kerb;

  if (!p)
    return;

  kerb = (struct ruby_krb5 *)p;

  // kerb->creds is not a pointer, so we can't check for NULL; however, the
  // implementation of krb5_free_cred_contents does do NULL checking, so it is
  // safe (at least in the MIT version) to call it unconditionally
  krb5_free_cred_contents(kerb->ctx, &kerb->creds);
  if (kerb->princ)
    krb5_free_principal(kerb->ctx, kerb->princ);
  if (kerb->ctx)
    krb5_free_context(kerb->ctx);
  memset(kerb, 0, sizeof(struct ruby_krb5));
  free(kerb);
}

/*
 * call-seq:
 *   new
 *
 * Create a new Krb5Auth::Krb5 object.  This must be called before any other methods are called.  Returns true on success, raises Krb5Auth::Krb5::Exception on failure.
 */
static VALUE Krb5_new(VALUE self)
{
  struct ruby_krb5 *kerb;
  krb5_error_code krbret;

  kerb = (struct ruby_krb5 *)malloc(sizeof(struct ruby_krb5));
  if (kerb == NULL) {
    OOM_EXCEPT();
    return Qnil;
  }

  memset(kerb, 0, sizeof(struct ruby_krb5));

  krbret = krb5_init_context(&kerb->ctx);
  if (krbret) {
    Krb5_register_error(krbret);    
    return Qnil;
  }

  return Data_Wrap_Struct(cKrb5, NULL, kerb_free, kerb);
}

/*
 * call-seq:
 *   get_default_realm -> string
 *
 * Call krb5_get_default_realm() to get the default realm.  Returns the default realm on success, raises Krb5Auth::Krb5::Exception on failure.
 */
static VALUE Krb5_get_default_realm(VALUE self)
{
  struct ruby_krb5 *kerb;
  char *realm;
  VALUE result;
  krb5_error_code krbret;

  Data_Get_Struct(self, struct ruby_krb5, kerb);
  if (!kerb) {
    NOSTRUCT_EXCEPT();
    return Qfalse;
  }

  krbret = krb5_get_default_realm(kerb->ctx, &realm);
  if (krbret) {
    Krb5_register_error(krbret);    
    return Qnil;
  }

  result = rb_str_new2(realm);

  free(realm);

  return result;
}

/*
 * call-seq:
 *   get_default_principal -> string
 *
 * Call krb5_cc_get_principal() to get the principal from the default cachefile.  Returns the default principal on success, raises Krb5Auth::Krb5::Exception on failure.
 */
static VALUE Krb5_get_default_principal(VALUE self)
{
  struct ruby_krb5 *kerb;
  char *princ_name;
  VALUE result;
  krb5_error_code krbret;
  krb5_ccache cc;

  Data_Get_Struct(self, struct ruby_krb5, kerb);
  if (!kerb) {
    NOSTRUCT_EXCEPT();
    return Qfalse;
  }

  krbret = krb5_cc_default(kerb->ctx, &cc);
  if (krbret) {
    Krb5_register_error(krbret);
    return Qfalse;
  }

  krbret = krb5_cc_get_principal(kerb->ctx, cc, &kerb->princ);
  if (krbret) {
    krb5_cc_close(kerb->ctx, cc);
    Krb5_register_error(krbret);    
    return Qnil;
  }

  krb5_cc_close(kerb->ctx, cc);

  krbret = krb5_unparse_name(kerb->ctx, kerb->princ, &princ_name);
  if (krbret) {
    Krb5_register_error(krbret);    
    return Qnil;
  }

  result = rb_str_new2(princ_name);

  free(princ_name);

  return result;
}

/*
 * call-seq:
 *   get_init_creds_password(username, password)
 *
 * Call krb5_get_init_creds_password() to get credentials based on a username and password.  Returns true on success, raises Krb5Auth::Krb5::Exception on failure.
 */
static VALUE Krb5_get_init_creds_password(VALUE self, VALUE _user, VALUE _pass)
{
  Check_Type(_user,T_STRING);
  Check_Type(_pass,T_STRING);
  char *user = STR2CSTR(_user);
  char *pass = STR2CSTR(_pass);

  struct ruby_krb5 *kerb;
  krb5_error_code krbret;

  Data_Get_Struct(self, struct ruby_krb5, kerb);
  if (!kerb) {
    NOSTRUCT_EXCEPT();
    return Qfalse;
  }

  krbret = krb5_parse_name(kerb->ctx, user, &kerb->princ);
  if (krbret) {
    goto failed_pass;
  }

  krbret = krb5_get_init_creds_password(kerb->ctx, &kerb->creds, kerb->princ,
					pass, 0, NULL, 0,NULL, NULL);
  if (krbret) {
    goto failed_pass;
  }

  return Qtrue;

 failed_pass:
  Krb5_register_error(krbret);

  // we will never reach here, since Krb5_register_error will rb_raise().  just
  // leave it to shut the compiler up
  return Qfalse;
}

/*
 * call-seq:
 *   get_init_creds_keytab([principal][,keytab])
 *
 * Call krb5_get_init_creds_keytab() to get credentials based on a keytab.  With no parameters, gets the default principal (probably the username@DEFAULT_REALM) from the default keytab (as configured in /etc/krb5.conf).  With one parameter, get the named principal from the default keytab (as configured in /etc/krb5.conf).  With two parameters, get the named principal from the named keytab.  Returns true on success, raises Krb5Auth::Krb5::Exception on failure.
 */
static VALUE Krb5_get_init_creds_keytab(int argc, VALUE *argv, VALUE self)
{
  char *princ;
  char *keytab_name;
  struct ruby_krb5 *kerb;
  krb5_error_code krbret;
  krb5_keytab keytab;

  keytab = NULL;

  if (argc == 0) {
    keytab_name = NULL;
    princ = NULL;
  }
  else if (argc == 1) {
    Check_Type(argv[0], T_STRING);
    princ = STR2CSTR(argv[0]);
    keytab_name = NULL;
  }
  else if (argc == 2) {
    Check_Type(argv[0], T_STRING);
    Check_Type(argv[1], T_STRING);
    princ = STR2CSTR(argv[0]);
    keytab_name = STR2CSTR(argv[1]);
  }
  else {
    rb_raise(rb_eRuntimeError, "Invalid arguments");
  }

  Data_Get_Struct(self, struct ruby_krb5, kerb);
  if (!kerb) {
    NOSTRUCT_EXCEPT();
    return Qfalse;
  }

  if (keytab_name != NULL) {
    krbret = krb5_kt_resolve(kerb->ctx, keytab_name, &keytab);
    if (krbret) {
      goto failed_keytab;
    }
  }
  // implicit else: if we weren't passed a keytab name, just leave keytab as
  // NULL to use the default

  if (princ != NULL) {
    krbret = krb5_parse_name(kerb->ctx, princ, &kerb->princ);
  }
  else {
    // if we weren't passed a principal, we just get the default principal
    // (which is generally the hostname)
    krbret = krb5_sname_to_principal(kerb->ctx, NULL, NULL, KRB5_NT_SRV_HST,
				     &kerb->princ);
  }
  if (krbret) {
    goto failed_keytab;
  }

  krbret = krb5_get_init_creds_keytab(kerb->ctx, &kerb->creds, kerb->princ,
				      keytab, 0, NULL, NULL);
  if (krbret) {
    goto failed_keytab;
  }

  if (keytab)
    krb5_kt_close(kerb->ctx, keytab);

  return Qtrue;

 failed_keytab:
  if (keytab)
    krb5_kt_close(kerb->ctx, keytab);

  Krb5_register_error(krbret);

  // we will never reach here, since Krb5_register_error will rb_raise().  just
  // leave it to shut the compiler up
  return Qfalse;
}

/*
 * call-seq:
 *   set_password(new_password)
 *
 * Call krb5_set_password to set the password for this credential to new_password.  This requires that the credentials have already been fetched via Krb5.get_init_creds_password or Krb5.get_init_creds_keytab.  Returns true on success, raises Krb5Auth::Krb5::Exception on failure.
 */
static VALUE Krb5_change_password(VALUE self, VALUE _newpass)
{
  Check_Type(_newpass,T_STRING);
  char *newpass = STR2CSTR(_newpass);

  struct ruby_krb5 *kerb;
  krb5_error_code krbret;
  int pw_result;
  krb5_data pw_res_string, res_string;

  Data_Get_Struct(self, struct ruby_krb5, kerb);
  if (!kerb) {
    NOSTRUCT_EXCEPT();
    return Qfalse;
  }

  krbret = krb5_set_password(kerb->ctx, &kerb->creds, newpass, NULL,
			     &pw_result, &pw_res_string, &res_string );
  if (krbret) {
    Krb5_register_error(krbret);
    return Qfalse;
  }

  return Qtrue;
}

/*
 * call-seq:
 *   cache([cache_name])
 *
 * Call krb5_cc_store_cred to store credentials in a cachefile.  With no parameters, it stores the credentials in the default cachefile.  With one parameter, it stores the credentials in the named cachefile.  This requires that the credentials have already been fetched via Krb5.get_init_creds_password or Krb5.get_init_creds_keytab.  Returns true on success, raises Krb5Auth::Krb5::Exception on failure.
 */
static VALUE Krb5_cache_creds(int argc, VALUE *argv, VALUE self)
{
  struct ruby_krb5 *kerb;
  krb5_error_code krbret;
  char *cache_name;
  krb5_ccache cc;

  if (argc == 0) {
    cache_name = NULL;
  }
  else if (argc == 1) {
    Check_Type(argv[0], T_STRING);
    cache_name = STR2CSTR(argv[0]);
  }
  else {
    rb_raise(rb_eRuntimeError, "Invalid arguments");
  }

  Data_Get_Struct(self, struct ruby_krb5, kerb);
  if (!kerb) {
    NOSTRUCT_EXCEPT();
    return Qfalse;
  }

  if (!kerb->princ) {
    // OK, it looks like they are trying to cache credentials that they don't
    // yet have; just throw an exception so we don't segfault later
    rb_raise(cKrb5_Exception, "%s", "Attempting to cache before obtaining credentials");
    return Qfalse;
  }

  if (cache_name == NULL) {
    krbret = krb5_cc_default(kerb->ctx, &cc);
  }
  else {
    krbret = krb5_cc_resolve(kerb->ctx, cache_name, &cc);
  }

  if (krbret) {
    goto fail_cache;
  }

  krbret = krb5_cc_initialize(kerb->ctx, cc, kerb->princ);
  if (krbret) {
    goto fail_free_cc;
  }

  krbret = krb5_cc_store_cred(kerb->ctx, cc, &kerb->creds);
  if (krbret) {
    goto fail_free_cc;
  }

  krb5_cc_close(kerb->ctx, cc);

  return Qtrue;

 fail_free_cc:
  krb5_cc_close(kerb->ctx, cc);

 fail_cache:
  Krb5_register_error(krbret);

  // we will never reach here, since Krb5_register_error will rb_raise().  just
  // leave it to shut the compiler up
  return Qfalse;
}

/*
 * call-seq:
 *   list_cache([cache_name]) -> array
 *
 * Call krb5_cc_next_cred to fetch credentials from a cachefile.  With no parameters, it fetches the credentials in the default cachefile.  With one parameter, it fetches the credentials in the named cachefile.  Returns a list of Krb5Auth::Krb5::Cred objects on success, raises Krb5Auth::Krb5::Exception on failure.
 */
static VALUE Krb5_list_cache_creds(int argc, VALUE *argv, VALUE self)
{
  struct ruby_krb5 *kerb;
  krb5_error_code krbret;
  char *cache_name;
  krb5_ccache cc;
  krb5_cc_cursor cur;
  krb5_creds creds;
  char *name;
  char *sname;
  krb5_ticket *tkt;
  VALUE result;
  VALUE line;
    
  if (argc == 0) {
    cache_name = NULL;
  }
  else if (argc == 1) {
    Check_Type(argv[0], T_STRING);
    cache_name = STR2CSTR(argv[0]);
  }
  else {
    rb_raise(rb_eRuntimeError, "Invalid arguments");
  }

  Data_Get_Struct(self, struct ruby_krb5, kerb);
  if (!kerb) {
    NOSTRUCT_EXCEPT();
    return Qfalse;
  }

  if (cache_name == NULL) {
    krbret = krb5_cc_default(kerb->ctx, &cc);
  }
  else {
    krbret = krb5_cc_resolve(kerb->ctx, cache_name, &cc);
  }

  if (krbret) {
    goto cache_fail_raise;
  }

  krbret = krb5_cc_start_seq_get(kerb->ctx, cc, &cur);
  if (krbret) {
    goto cache_fail_close;
  }

  result = rb_ary_new();
  while (!(krbret = krb5_cc_next_cred(kerb->ctx, cc, &cur, &creds))) {
    krbret = krb5_unparse_name(kerb->ctx, creds.client, &name);
    if (krbret) {
      krb5_free_cred_contents(kerb->ctx, &creds);
      break;
    }
    krbret = krb5_unparse_name(kerb->ctx, creds.server, &sname);
    if (krbret) {
      free(name);
      krb5_free_cred_contents(kerb->ctx, &creds);
      break;
    }
    krbret = krb5_decode_ticket(&creds.ticket, &tkt);
    if (krbret) {
      free(sname);
      free(name);
      krb5_free_cred_contents(kerb->ctx, &creds);
      break;
    }
    line = rb_class_new_instance(0, NULL, cCred);
    rb_iv_set(line, "@client", rb_str_new2(name));
    rb_iv_set(line, "@server", rb_str_new2(sname));
    rb_iv_set(line, "@starttime", INT2NUM(creds.times.starttime));
    rb_iv_set(line, "@authtime", INT2NUM(creds.times.authtime));
    rb_iv_set(line, "@endtime", INT2NUM(creds.times.endtime));
    rb_iv_set(line, "@ticket_flags", INT2NUM(creds.ticket_flags));
    rb_iv_set(line, "@cred_enctype", INT2NUM(creds.keyblock.enctype));
    rb_iv_set(line, "@ticket_enctype", INT2NUM(tkt->enc_part.enctype));
    rb_ary_push(result, line);
    krb5_free_ticket(kerb->ctx, tkt);
    free(sname);
    free(name);
    krb5_free_cred_contents(kerb->ctx, &creds);
  }

  if (krbret != KRB5_CC_END) {
    // FIXME: do we need to free up "result" here?  There will be no
    // references to it, so I think the garbage collector will pick it up,
    // but I'm not sure.

    goto cache_fail_close;
  }

  krbret = krb5_cc_end_seq_get(kerb->ctx, cc, &cur);

  krb5_cc_close(kerb->ctx, cc);

  return result;

 cache_fail_close:
  krb5_cc_close(kerb->ctx, cc);

 cache_fail_raise:
  Krb5_register_error(krbret);

  return Qfalse;
}

/*
 * call-seq:
 *   destroy([cache_name])
 *
 * Call krb5_cc_destroy to destroy all credentials in a cachefile.  With no parameters, it destroys the credentials in the default cachefile.  With one parameter, it destroys the credentials in the named cachefile.  Returns true on success, raises Krb5Auth::Krb5::Exception on failure.
 */
static VALUE Krb5_destroy_creds(int argc, VALUE *argv, VALUE self)
{
  struct ruby_krb5 *kerb;
  krb5_error_code krbret;
  char *cache_name;
  krb5_ccache cc;

  if (argc == 0) {
    cache_name = NULL;
  }
  else if (argc == 1) {
    Check_Type(argv[0], T_STRING);
    cache_name = STR2CSTR(argv[0]);
  }
  else {
    rb_raise(rb_eRuntimeError, "Invalid arguments");
  }

  Data_Get_Struct(self, struct ruby_krb5, kerb);
  if (!kerb) {
    NOSTRUCT_EXCEPT();
    return Qfalse;
  }

  if (cache_name == NULL) {
    krbret = krb5_cc_default(kerb->ctx, &cc);
  }
  else {
    krbret = krb5_cc_resolve(kerb->ctx, cache_name, &cc);
  }

  if (krbret) {
    Krb5_register_error(krbret);
    return Qfalse;
  }

  krbret = krb5_cc_destroy(kerb->ctx, cc);
  if (krbret) {
    Krb5_register_error(krbret);
    return Qfalse;
  }

  // NOTE: we don't need to call krb5_cc_close here since it is freed
  // automatically by krb5_cc_destroy()

  return Qtrue;
}

/*
 * call-seq:
 *   close
 *
 * Free up all memory associated with this object.  After this is called, no more methods may be called against this object.
 */
static VALUE Krb5_close(VALUE self)
{
  struct ruby_krb5 *kerb;

  Data_Get_Struct(self, struct ruby_krb5, kerb);
  if (kerb) {
    kerb_free(kerb);
    DATA_PTR(self) = NULL;
  }

  return Qnil;
}

/*
 * = Ruby bindings for kerberos
 *
 * The module Krb5Auth provides bindings to kerberos version 5 libraries
 */
void Init_krb5_auth()
{
  mKerberos = rb_define_module("Krb5Auth");

  cKrb5 = rb_define_class_under(mKerberos,"Krb5", rb_cObject);

  cKrb5_Exception = rb_define_class_under(cKrb5, "Exception", rb_eStandardError);

  cCred = rb_define_class_under(cKrb5, "Cred", rb_cObject);
  rb_define_attr(cCred, "client", 1, 0);
  rb_define_attr(cCred, "server", 1, 0);
  rb_define_attr(cCred, "starttime", 1, 0);
  rb_define_attr(cCred, "authtime", 1, 0);
  rb_define_attr(cCred, "endtime", 1, 0);
  rb_define_attr(cCred, "ticket_flags", 1, 0);
  rb_define_attr(cCred, "cred_enctype", 1, 0);
  rb_define_attr(cCred, "ticket_enctype", 1, 0);

#define DEF_FLAG_CONST(name) \
  rb_define_const(cCred, #name, INT2NUM(name))

  DEF_FLAG_CONST(TKT_FLG_FORWARDABLE);
  DEF_FLAG_CONST(TKT_FLG_FORWARDED);
  DEF_FLAG_CONST(TKT_FLG_PROXIABLE);
  DEF_FLAG_CONST(TKT_FLG_PROXY);
  DEF_FLAG_CONST(TKT_FLG_MAY_POSTDATE);
  DEF_FLAG_CONST(TKT_FLG_POSTDATED);
  DEF_FLAG_CONST(TKT_FLG_INVALID);
  DEF_FLAG_CONST(TKT_FLG_RENEWABLE);
  DEF_FLAG_CONST(TKT_FLG_INITIAL);
  DEF_FLAG_CONST(TKT_FLG_HW_AUTH);
  DEF_FLAG_CONST(TKT_FLG_PRE_AUTH);
  DEF_FLAG_CONST(TKT_FLG_TRANSIT_POLICY_CHECKED);
  DEF_FLAG_CONST(TKT_FLG_OK_AS_DELEGATE);
  DEF_FLAG_CONST(TKT_FLG_ANONYMOUS);

#undef DEF_FLAG_CONST

#define DEF_ENC_CONST(name) \
  rb_define_const(cCred, #name, INT2NUM(name))

  DEF_ENC_CONST(ENCTYPE_NULL);
  DEF_ENC_CONST(ENCTYPE_DES_CBC_CRC);
  DEF_ENC_CONST(ENCTYPE_DES_CBC_MD4);
  DEF_ENC_CONST(ENCTYPE_DES_CBC_MD5);
  DEF_ENC_CONST(ENCTYPE_DES_CBC_RAW);
  DEF_ENC_CONST(ENCTYPE_DES3_CBC_SHA);
  DEF_ENC_CONST(ENCTYPE_DES3_CBC_RAW);
  DEF_ENC_CONST(ENCTYPE_DES_HMAC_SHA1);
  DEF_ENC_CONST(ENCTYPE_DES3_CBC_SHA1);
  DEF_ENC_CONST(ENCTYPE_AES128_CTS_HMAC_SHA1_96);
  DEF_ENC_CONST(ENCTYPE_AES256_CTS_HMAC_SHA1_96);
  DEF_ENC_CONST(ENCTYPE_ARCFOUR_HMAC);
  DEF_ENC_CONST(ENCTYPE_ARCFOUR_HMAC_EXP);
  DEF_ENC_CONST(ENCTYPE_UNKNOWN);
#undef DEF_ENC_CONST

  rb_define_singleton_method(cKrb5, "new", Krb5_new, 0);
  rb_define_method(cKrb5, "get_init_creds_password", Krb5_get_init_creds_password, 2);
  rb_define_method(cKrb5, "get_init_creds_keytab", Krb5_get_init_creds_keytab, -1);
  rb_define_method(cKrb5, "get_default_realm", Krb5_get_default_realm, 0);
  rb_define_method(cKrb5, "get_default_principal", Krb5_get_default_principal, 0);
  rb_define_method(cKrb5, "change_password", Krb5_change_password, 1);
  rb_define_method(cKrb5, "cache", Krb5_cache_creds, -1);
  rb_define_method(cKrb5, "list_cache", Krb5_list_cache_creds, -1);
  rb_define_method(cKrb5, "destroy", Krb5_destroy_creds, -1);
  rb_define_method(cKrb5, "close", Krb5_close, 0);
}
