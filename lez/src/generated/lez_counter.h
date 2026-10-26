/* Auto-generated C header for lez_counter FFI. DO NOT EDIT. */
#ifndef LEZ_COUNTER_FFI_H
#define LEZ_COUNTER_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

/* initialize instruction */
char* lez_counter_initialize(const char* args_json);

/* increment instruction */
char* lez_counter_increment(const char* args_json);

/* fetch counter account state */
char* lez_counter_fetch_counter(const char* args_json);

/* wallet helpers */
char* lez_counter_check_connection(const char* args_json);
char* lez_counter_inspect_account(const char* args_json);
char* lez_counter_list_accounts(const char* args_json);
char* lez_counter_create_account(const char* args_json);

void lez_counter_free_string(char* s);
char* lez_counter_version(void);
char* lez_counter_program_id(void);
char* lez_counter_decode_account(const char* args_json);

#ifdef __cplusplus
}
#endif

#endif /* LEZ_COUNTER_FFI_H */
