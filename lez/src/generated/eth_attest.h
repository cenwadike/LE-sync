/* Auto-generated C header for eth_attest FFI. DO NOT EDIT. */
#ifndef ETH_ATTEST_FFI_H
#define ETH_ATTEST_FFI_H

#ifdef __cplusplus
extern "C" {
#endif

/* init_instance instruction */
char* eth_attest_init_instance(const char* args_json);

/* begin_update instruction */
char* eth_attest_begin_update(const char* args_json);

/* miller_update instruction */
char* eth_attest_miller_update(const char* args_json);

/* finish_update instruction */
char* eth_attest_finish_update(const char* args_json);

/* attest_state instruction */
char* eth_attest_attest_state(const char* args_json);

/* attest_log instruction */
char* eth_attest_attest_log(const char* args_json);

/* fetch instance account state */
char* eth_attest_fetch_instance(const char* args_json);

/* fetch store account state */
char* eth_attest_fetch_store(const char* args_json);

/* fetch records account state */
char* eth_attest_fetch_records(const char* args_json);

/* fetch job account state */
char* eth_attest_fetch_job(const char* args_json);

/* fetch statement account state */
char* eth_attest_fetch_statement(const char* args_json);

/* wallet helpers */
char* eth_attest_check_connection(const char* args_json);
char* eth_attest_inspect_account(const char* args_json);
char* eth_attest_list_accounts(const char* args_json);
char* eth_attest_create_account(const char* args_json);

void eth_attest_free_string(char* s);
char* eth_attest_version(void);
char* eth_attest_program_id(void);
char* eth_attest_decode_account(const char* args_json);

#ifdef __cplusplus
}
#endif

#endif /* ETH_ATTEST_FFI_H */
