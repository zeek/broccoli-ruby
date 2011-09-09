%module "broccoli"

%include cpointer.i
%include typemaps.i

%{
/* Includes the header in the wrapper code */
#include "broccoli.h"
%}

%{
  
/* Convert Ruby String to BroString */
BroString to_brostring(VALUE obj){
  if(!NIL_P(obj)){
    Check_Type(obj, T_STRING);
    BroString bs;
    bro_string_set(&bs, STR2CSTR(obj));
    return bs;
  }
}

static void
wrap_BroCompactEventFunc(BroConn *bc, void *user_data, BroEvMeta *meta)
{
  int i;
  int callback_arity = 0;
  VALUE proc = (VALUE)user_data;
  VALUE out[15] = {Qnil,Qnil,Qnil,Qnil,Qnil,Qnil,Qnil,Qnil,
                   Qnil,Qnil,Qnil,Qnil,Qnil,Qnil,Qnil};
    
  callback_arity = NUM2INT(rb_funcall(proc, rb_intern("arity"), 0));
  if ( callback_arity != meta->ev_numargs ) 
  {
    printf("ERROR: callback has %d arguments when it should have %d arguments.\n", 
           callback_arity,
           meta->ev_numargs);
  }
  for(i=0 ; i < meta->ev_numargs ; i++) 
  {
    //printf("Loop #%i\n", i);
    switch (meta->ev_args[i].arg_type)
    {
      case BRO_TYPE_RECORD:
        //printf("Found a BroRecord in the callback wrapper\n");
        out[i] = SWIG_NewPointerObj(SWIG_as_voidptr(meta->ev_args[i].arg_data), SWIGTYPE_p_bro_record, 0 |  0 );
        break;
      case BRO_TYPE_PORT:
        out[i] = SWIG_NewPointerObj(SWIG_as_voidptr(meta->ev_args[i].arg_data), SWIGTYPE_p_bro_port, 0 |  0 );
        break;
      case BRO_TYPE_INT:
      case BRO_TYPE_ENUM:
        //printf("Found an integer in the callback wrapper\n");
        out[i] = INT2NUM( *((int *) meta->ev_args[i].arg_data) );
        break;
      case BRO_TYPE_BOOL:
        //printf("Found a boolean in the callback wrapper\n");
        out[i] = *((int *) meta->ev_args[i].arg_data) ? Qtrue : Qfalse;
        break;
      case BRO_TYPE_STRING:
        //printf("Found a BroString in the callback wrapper\n");
        out[i] = rb_str_new( (char*) bro_string_get_data( (BroString*) meta->ev_args[i].arg_data ), 
                                     bro_string_get_length( (BroString*) meta->ev_args[i].arg_data ) );    
        break;
      case BRO_TYPE_TIME:
      case BRO_TYPE_DOUBLE:
      case BRO_TYPE_INTERVAL:
        //printf("Found a double in the callback wrapper\n");
        out[i] = rb_float_new( *((double *) meta->ev_args[i].arg_data) );
        break;
      case BRO_TYPE_COUNT:
        //printf("Found a 32bit unsigned integer in the callback wrapper\n");
        out[i] = UINT2NUM( *((uint32 *) meta->ev_args[i].arg_data) );
        break;
      case BRO_TYPE_IPADDR:
        //printf("Found an ip address... making it a string\n");
        //output ip addresses as strings that can be unpacked from ruby.
        out[i] = rb_str_new2((char *) meta->ev_args[i].arg_data);
        break;
	  case BRO_TYPE_COUNTER:
	  case BRO_TYPE_TIMER:
	  case BRO_TYPE_PATTERN:
	  case BRO_TYPE_SUBNET:
	  case BRO_TYPE_ANY:
	  case BRO_TYPE_TABLE:
	  case BRO_TYPE_UNION:
	  case BRO_TYPE_LIST:
	  case BRO_TYPE_FUNC:
	  case BRO_TYPE_FILE:
	  case BRO_TYPE_VECTOR:
	  case BRO_TYPE_ERROR:
	  case BRO_TYPE_MAX:
		printf("Type not yet handled.\n");
		break;
      default:
        printf("Invalid type was registered for callback!\n");
        break;
    }
  }

  // Call the ruby proc object
  rb_funcall2(proc, rb_intern("call"), callback_arity, out);
  
  bc = NULL;
  user_data = NULL;
}

%}

%typemap(in) (BroCompactEventFunc func, void *user_data)
{
  $1 = (BroCompactEventFunc) wrap_BroCompactEventFunc;
  $2 = (void *)$input;
}

// Clean up bro strings after they're used
%typemap(ret) int bro_record_add_val,
              int bro_record_set_named_val,
              int bro_record_set_nth_val
{
  if(arg3 == BRO_TYPE_STRING) { bro_string_cleanup(arg5); }
}
%typemap(ret) int bro_event_add_val
{
  if(arg2 == BRO_TYPE_STRING) { bro_string_cleanup(arg4); }
}

//bro_record_add_val
//bro_record_set_named_val
//bro_record_set_nth_val
//bro_event_add_val
//bro_event_set_val
%typemap(in) (int type, const char *type_name, const void *val)
{
  int tmp_int;
  double tmp_double;
  uint32 tmp_uint32;
  BroString tmp_brostring;
  void *tmp_swigpointer;
  int res;
  int type;
  VALUE value;
  VALUE type_name;
  
  // Use ruby's array accessor method to get the type, type_name and value
  type = NUM2INT(rb_funcall($input, rb_intern("at"), 1, INT2NUM(0)));
  $1 = type;
  type_name = rb_funcall($input, rb_intern("at"), 1, INT2NUM(1));  
  if ( rb_funcall(type_name, rb_intern("=="), 1, Qnil) == Qtrue )
  {
    $2 = NULL;
  } else {
    Check_Type(type_name, T_STRING);
    $2 = (char *)STR2CSTR(type_name);
  }
  value = rb_funcall($input, rb_intern("at"), 1, INT2NUM(2));
  
  switch(type)
  {
    case BRO_TYPE_INT:
    case BRO_TYPE_ENUM:
      //printf("Matched on Fixnum!  Storing value as an int (%i)\n", NUM2INT($input));
      tmp_int = NUM2INT(value);
      $3 = &tmp_int;
      break;
      
    case BRO_TYPE_BOOL:
      //printf("Matched on boolean!  Storing value as an integer\n");
      tmp_int = value ? 1 : 0;
      $3 = &tmp_int;
      break;
      
    case BRO_TYPE_TIME:
    case BRO_TYPE_DOUBLE:
    case BRO_TYPE_INTERVAL:
      //printf("Storing value as a double (%f)\n", rb_num2dbl($input));
      tmp_double = rb_num2dbl(value);
      $3 = &tmp_double;
      break;
      
    case BRO_TYPE_COUNT:
    case BRO_TYPE_IPADDR:
      //printf("Storing value as a uint32\n");
      tmp_uint32 = rb_num2ulong(value);
      $3 = &tmp_uint32;
      break;
      
    case BRO_TYPE_STRING:
      //printf("Storing value as a BroString\n");
      tmp_brostring = to_brostring(value);
      $3 = &tmp_brostring;
      break;
      
    case BRO_TYPE_PORT:
      //printf("Storing value as a BroPort\n");
      res = SWIG_ConvertPtr(value, &tmp_swigpointer, SWIGTYPE_p_bro_port, 0);
      if (!SWIG_IsOK(res)) {
        SWIG_exception_fail(SWIG_ArgError(res), "the value for $symname was supposed to be a BroPort"); 
      }
      $3 = (BroPort *)(tmp_swigpointer);
      break;
      
    case BRO_TYPE_SUBNET:
      //printf("Storing value as a BroSubnet\n");
      res = SWIG_ConvertPtr(value, &tmp_swigpointer, SWIGTYPE_p_bro_subnet, 0);
      if (!SWIG_IsOK(res)) {
        SWIG_exception_fail(SWIG_ArgError(res), "the value for $symname was supposed to be a BroSubnet"); 
      }
      $3 = (BroSubnet *)(tmp_swigpointer);
      break;

    case BRO_TYPE_RECORD:
      //printf("Storing value as a BroRecord\n");
      res = SWIG_ConvertPtr(value, &tmp_swigpointer, SWIGTYPE_p_bro_record, 0);
      if (!SWIG_IsOK(res)) {
        SWIG_exception_fail(SWIG_ArgError(res), "the value for $symname was supposed to be a BroRecord"); 
      }
      $3 = (BroRecord *)(tmp_swigpointer);
      break;
    
    default:
      printf("ERROR($symname): no valid type defined\n");
      break;
  }
}


%typemap(out) void* bro_conn_data_get {
  if( strcmp(arg2, "service") == 0 ||
      strcmp(arg2, "addl") == 0 ||
      strcmp(arg2, "history") == 0) {
    $result = rb_str_new( (char *) bro_string_get_data((BroString*) $1), 
                                   bro_string_get_length((BroString*) $1) );    
  }
  else if( strcmp(arg2, "") == 0 ) {
    
  }
  else
  {
    printf("Couldn't find the correct data type to convert to...\n");
    $result = Qnil;
  }
} 

%typemap(in) (const char *name, int *type) {
  $1 = (char*) STR2CSTR($input);
  // This is to pass arg 3 (int *type) as a value-result argument
  int mytemp3 = 0;
  $2 = &mytemp3;
}

%typemap(in) (int num, int *type) {
  $1 = NUM2INT($input);
  // This is to pass arg 3 (int *type) as a value-result argument
  int mytemp3 = 0;
  $2 = &mytemp3;
}

%typemap(out) void* bro_record_get_named_val, 
              void* bro_record_get_nth_val {
  switch(*arg3)
  {
    case BRO_TYPE_BOOL:
      //printf("Ruby: Getting data matched on boolean\n");
      $result = (((int *) $1) ? Qtrue : Qfalse);    
      break;
    
    case BRO_TYPE_INT:
    case BRO_TYPE_ENUM:
      //printf("Ruby: Getting data matched on int\n");
      $result = INT2NUM( *((int *) $1) );    
      break;
    
    case BRO_TYPE_TIME:
    case BRO_TYPE_DOUBLE:
    case BRO_TYPE_INTERVAL:
      //printf("Ruby: Getting data matched on time\n");
      $result = rb_float_new( *((double *) $1) );
      break;
    
    case BRO_TYPE_STRING:
      //printf("Ruby: getting data matched on string\n");
      $result = rb_str_new( (char *)((BroString *) $1)->str_val, ((BroString *) $1)->str_len );
      break;
      
    case BRO_TYPE_COUNT:
      //printf("Ruby: Getting data matched on uint32\n");   
      $result = ULONG2NUM( *((uint32 *) $1) );
      break;
      
    case BRO_TYPE_IPADDR:
      //printf("I found an ip address... making it a network byte ordered string\n");
      $result = rb_str_new2( (char *) $1);
      break;
    
    case BRO_TYPE_RECORD:
      //printf("Ruby: Getting data matched as a BroRecord\n");
      $result = SWIG_NewPointerObj(SWIG_as_voidptr( (BroRecord *) $1 ), SWIGTYPE_p_bro_record, 0);
      break;
  
    case BRO_TYPE_PORT:
      //printf("Ruby: Getting data matched as a BroPort\n");
      $result = SWIG_NewPointerObj(SWIG_as_voidptr( (BroPort *) $1 ), SWIGTYPE_p_bro_port, 0);
      break;
      
    default:
      printf("No type recognized when getting value\n");
  }
} 

// When methods output an integer, it's usually boolean, make it so.
%typemap(out) int bro_conn_connect,
              int bro_conn_alive,
              int bro_conn_delete,
              int bro_conn_process_input,
              int bro_event_add_val,
              int bro_event_set_val,
              int bro_event_send,
              int bro_record_set_nth_val,
              int bro_record_set_named_val,
              int bro_packet_send "$result = $1 ? Qtrue:Qfalse;"

// Allow "true" and "false" for setting debug vars
%typemap(varin) int bro_debug_calltrace, 
                int bro_debug_messages "$1 = $input ? 1:0;"
                
%typemap(in) uchar * "$1 = (uchar*)STR2CSTR($input);"
%typemap(out) uchar * "$result = rb_str_new2((char*)$1);"

%predicate bro_conn_alive(const BroConn *bc);

BroString to_brostring(VALUE obj);

//********************
// Header file stuff below
//********************
%include "broccoli.h"

//// Changes from the default header file.
////void* bro_record_get_named_val(BroRecord *rec, const char *name, int *OUTPUT);
////int bro_conf_get_int(const char *val_name, int *OUTPUT);
////int bro_conf_get_dbl(const char *val_name, double *OUTPUT);
//
//extern int bro_debug_calltrace;
//extern int bro_debug_messages;
//
//#define BRO_TYPE_UNKNOWN           0
//#define BRO_TYPE_BOOL              1
//#define BRO_TYPE_INT               2
//#define BRO_TYPE_COUNT             3
//#define BRO_TYPE_COUNTER           4
//#define BRO_TYPE_DOUBLE            5
//#define BRO_TYPE_TIME              6
//#define BRO_TYPE_INTERVAL          7
//#define BRO_TYPE_STRING            8
//#define BRO_TYPE_PATTERN           9
//#define BRO_TYPE_ENUM             10
//#define BRO_TYPE_TIMER            11
//#define BRO_TYPE_PORT             12
//#define BRO_TYPE_IPADDR           13
//#define BRO_TYPE_SUBNET           14
//#define BRO_TYPE_ANY              15
//#define BRO_TYPE_TABLE            16
//#define BRO_TYPE_UNION            17
//#define BRO_TYPE_RECORD           18
//#define BRO_TYPE_LIST             19
//#define BRO_TYPE_FUNC             20
//#define BRO_TYPE_FILE             21
//#define BRO_TYPE_VECTOR           22
//#define BRO_TYPE_ERROR            23
//#define BRO_TYPE_PACKET           24 /* CAUTION -- not defined in Bro! */
//#define BRO_TYPE_SET              25 /* ----------- (ditto) ---------- */
//#define BRO_TYPE_MAX              26
//
//#define BRO_CFLAG_NONE                      0
//#define BRO_CFLAG_RECONNECT           (1 << 0) /* Attempt transparent reconnects */
//#define BRO_CFLAG_ALWAYS_QUEUE        (1 << 1) /* Queue events sent while disconnected */
//#define BRO_CFLAG_SHAREABLE           (1 << 2) /* Allow sharing handle across threads/procs */
//#define BRO_CFLAG_DONTCACHE           (1 << 3) /* Ask peer not to use I/O cache */
//
//typedef unsigned int   uint32;
//typedef unsigned short uint16;
//typedef unsigned char  uchar;
//
//typedef struct bro_conn BroConn;
//typedef struct bro_event BroEvent;
//typedef struct bro_buf BroBuf;
//typedef struct bro_record BroRecord;
//
//typedef void (*BroCompactEventFunc) (BroConn *bc, void *user_data, 
//                                     int num_args, BroEvArg *args);
//typedef struct bro_val_meta {
//  int          val_type;   /* A BRO_TYPE_xxx constant */
//} BroValMeta;
//typedef struct bro_ev_arg {
//  void        *arg_data;   /* Pointer to the actual event argument */
//  BroValMeta  *arg_meta;   /* Pointer to metadata for the argument */
//} BroEvArg;
//
//typedef struct bro_string {
//  uint32       str_len;
//  uchar       *str_val;
//} BroString;
//
//typedef struct bro_port {
//  uint16       port_num;   /* port number in host byte order */
//  int          port_proto; /* IPPROTO_xxx */
//} BroPort;
//
//typedef struct bro_subnet
//{
//  uint32       sn_net;     /* IP address in network byte order */
//  uint32       sn_width;   /* Length of prefix to consider. */
//} BroSubnet;
//
//BroConn* bro_conn_new_str(const char *hostname,
//                          int flags);
//
//int bro_conn_connect (BroConn *bc);
//int bro_conn_process_input (BroConn *bc);
//int bro_conn_delete (BroConn *bc);
//int bro_conn_alive (const BroConn *bc);
//void* bro_conn_data_get (BroConn *bc, const char *key);
//void* bro_conn_data_del (BroConn *bc, const char *key);
//int bro_conn_get_fd (BroConn *bc);
//void bro_conn_adopt_events (BroConn *src, BroConn *dst);
//
//int bro_conf_get_int (const char *val_name, int *OUTPUT);
//int bro_conf_get_dbl (const char *val_name, double *OUTPUT);
//const char* bro_conf_get_str (const char *val_name);
////
////void        bro_string_init                 (BroString *bs);
////int         bro_string_set                  (BroString *bs,
////                                             const char *s);
////int         bro_string_set_data             (BroString *bs,
////                                             const uchar *data,
////                                             int data_len);
////const uchar* bro_string_get_data            (const BroString *bs);
////uint32      bro_string_get_length           (const BroString *bs);
////BroString*  bro_string_copy                 (BroString *bs);
////void        bro_string_cleanup              (BroString *bs);
////void        bro_string_free                 (BroString *bs);
//
//BroRecord* bro_record_new (void);
//int bro_record_add_val (BroRecord *rec, 
//                        const char *name,
//  				              int type, 
//  				              const char *type_name,
//  				              const void *val);
//void* bro_record_get_named_val (BroRecord *rec,
//                                const char *name,
//                                int *OUTPUT);
//void* bro_record_get_nth_val (BroRecord *rec,
//                              int num,
//                              int *type);
//int bro_record_set_nth_val (BroRecord *rec,
//                            int num,
//                            int type,
//                            const char *type_name,
//                            const void *val);
//int bro_record_set_named_val (BroRecord *rec,
//                              const char *name,
//                              int type,
//                              const char *type_name,
//                              const void *val);
//void bro_record_free (BroRecord *rec);
//                             
//BroEvent *bro_event_new (const char *event_name);
//                             
//int bro_event_add_val (BroEvent *be,
//                       int type,
//                       const char *type_name,
//                       const void *val);
//int bro_event_set_val (BroEvent *be, 
//                       int val_num,
//                       int type, 
//                       const char *type_name,
//                       const void *val);
//                             
//void bro_event_registry_add (BroConn *bc,
//                             const char *event_name,
//                             BroEventFunc func,
//                             void *user_data);
//void bro_event_registry_add_compact (BroConn *bc,
//                                     const char *event_name,
//                                     BroCompactEventFunc func,
//                                     void *user_data);
//void bro_event_registry_remove (BroConn *bc, 
//                                const char *event_name);
//void bro_event_registry_request (BroConn *bc);
//
//int bro_event_queue_length_max (BroConn *bc);
//int bro_event_queue_length (BroConn *bc);
//int bro_event_queue_flush (BroConn *bc);
//                             
//int bro_event_send (BroConn *bc,
//                    BroEvent *be);
//                   
//void bro_event_free (BroEvent *be);
//                             
//double bro_util_current_time (void);
//
//
//                            
