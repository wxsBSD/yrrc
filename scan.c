/* 
 * Copyright 2020 Wesley Shields <wxs@atarininja.org>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>

#include "cJSON.h"
#include "error.h"
#include "utils.h"
#include "yara.h"

int scan_callback(YR_SCAN_CONTEXT* ctx, int msg, void* data, void* user) {
  cJSON* match_name = NULL;
  cJSON* matches = user;
  YR_RULE* rule = data;

  if (msg == CALLBACK_MSG_RULE_MATCHING) {
    match_name = cJSON_CreateString(rule->identifier);
    if (match_name == NULL)
      return CALLBACK_ABORT;

    if (cJSON_AddItemToArray(matches, match_name) == 0) {
      cJSON_Delete(match_name);
      return CALLBACK_ABORT;
    }
  }

  return CALLBACK_CONTINUE;
}

int scan_files(cJSON* config, cJSON** json_map) {
  cJSON* elem = NULL;
  cJSON* matches = NULL;
  cJSON* yara_error = NULL;
  char* cache_dir = NULL;
  char* rules_file = NULL;
  char* hashes_file = NULL;
  char* hash = NULL;
  char* scan_file = NULL;
  YR_RULES* rules = NULL;
  int result = YRRC_NO_ERROR;

  result = get_string_from_config(config, YRRC_CONFIG_HASHES, &hashes_file);
  if (result != YRRC_NO_ERROR)
    return result;

  result = get_string_from_config(config, YRRC_CONFIG_RULES, &rules_file);
  if (result != YRRC_NO_ERROR)
    return result;

  result = get_string_from_config(config, YRRC_CACHE_DIR, &cache_dir);
  if (result != YRRC_NO_ERROR)
    return result;

  result = read_json_file(hashes_file, json_map);
  if (result != YRRC_NO_ERROR)
    return result;

  result = compile_rules(rules_file, &rules);
  if (result != YRRC_NO_ERROR) {
    cJSON_Delete(*json_map);
    return result;
  }

  // Use you cJSON_ArrayForEach to iterate over elements of an object.
  cJSON_ArrayForEach(elem, *json_map) {
    // XXX: Check to make sure this is a string...
    hash = elem->string;
    if (hash == NULL)
      continue;

    asprintf(&scan_file, "%s/%s", cache_dir, hash);
    if (scan_file == NULL) {
      cJSON_Delete(*json_map);
      yr_rules_destroy(rules);
      return YRRC_ERROR_NO_MEMORY;
    }

    matches = cJSON_CreateArray();
    if (matches == NULL) {
      free(scan_file);
      cJSON_Delete(*json_map);
      yr_rules_destroy(rules);
      return YRRC_ERROR_NO_MEMORY;
    }

    result = yr_rules_scan_file(
        rules,
        scan_file,
        SCAN_FLAGS_FAST_MODE | SCAN_FLAGS_REPORT_RULES_MATCHING,
        scan_callback,
        matches,
        0);

    free(scan_file);

    if (cJSON_AddItemToObject(elem, "matches", matches) == 0) {
      cJSON_Delete(*json_map);
      cJSON_Delete(matches);
      yr_rules_destroy(rules);
      return YRRC_ERROR_NO_MEMORY;
    }

    yara_error = cJSON_CreateNumber((double)result);
    if (yara_error == NULL) {
      cJSON_Delete(*json_map);
      yr_rules_destroy(rules);
      return YRRC_ERROR_NO_MEMORY;
    }

    if (cJSON_AddItemToObject(elem, "yara_error", yara_error) == 0) {
      cJSON_Delete(*json_map);
      cJSON_Delete(yara_error);
      yr_rules_destroy(rules);
      return YRRC_ERROR_NO_MEMORY;
    }
  }

  yr_rules_destroy(rules);

  return YRRC_NO_ERROR;
}
