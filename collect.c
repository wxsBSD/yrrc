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

#include "cJSON.h"
#include "error.h"
#include "utils.h"

int collect_hashes(cJSON* config, cJSON** json_map) {
  // This is the config key which holds the name of the field we need to look
  // for in the rule metadata.
  cJSON* meta_key = NULL;
  cJSON* expected_rules = NULL;
  cJSON* json_rule_name = NULL;
  cJSON* hash_obj = NULL;
  YR_RULES* rules = NULL;
  YR_RULE* rule = NULL;
  YR_META* meta = NULL;
  // This is the value of the config setting.
  char* meta_key_name = NULL;
  char* rules_file = NULL;
  int result = YRRC_NO_ERROR;

  result = get_string_from_config(config, YRRC_META_KEY, &meta_key_name);
  if (result != YRRC_NO_ERROR)
    return result;

  result = get_string_from_config(config, YRRC_CONFIG_RULES, &rules_file);
  if (result != YRRC_NO_ERROR)
    return result;

  result = compile_rules(rules_file, &rules);
  if (result != YRRC_NO_ERROR)
    return result;

  *json_map = cJSON_CreateObject();
  if (*json_map == NULL) {
    yr_rules_destroy(rules);
    return YRRC_ERROR_NO_MEMORY;
  }

  yr_rules_foreach(rules, rule) {
    yr_rule_metas_foreach(rule, meta) {
      if (meta->type == META_TYPE_STRING) {
        if (meta_key_name == NULL ||
            strncmp(meta->identifier, meta_key_name, strlen(meta_key_name)) != 0)
          continue;
        
        hash_obj = cJSON_GetObjectItem(*json_map, meta->string);
        if (hash_obj == NULL) {
          // Hash does not exist in our map, create it and add it.
          hash_obj = cJSON_CreateObject();
          if (hash_obj == NULL) {
            cJSON_Delete(*json_map);
            yr_rules_destroy(rules);
            return YRRC_ERROR_NO_MEMORY;
          }

          if (cJSON_AddItemToObject(*json_map, meta->string, hash_obj) == 0) {
            cJSON_Delete(hash_obj);
            cJSON_Delete(*json_map);
            yr_rules_destroy(rules);
            return YRRC_ERROR_NO_MEMORY;
          }

          // Since we now this is the first time seeing this hash, add the
          // "expected" array too.
          expected_rules = cJSON_AddArrayToObject(hash_obj, "expected");
          if (expected_rules == NULL) {
            cJSON_Delete(*json_map);
            yr_rules_destroy(rules);
            return YRRC_ERROR_NO_MEMORY;
          }
        } else {
          expected_rules = cJSON_GetObjectItem(hash_obj, "expected");
          if (expected_rules == NULL) {
            cJSON_Delete(*json_map);
            yr_rules_destroy(rules);
            return YRRC_ERROR_NO_MEMORY;
          }
        }

        json_rule_name = cJSON_CreateString(rule->identifier);
        if (json_rule_name == NULL) {
          cJSON_Delete(hash_obj);
          cJSON_Delete(*json_map);
          yr_rules_destroy(rules);
          return YRRC_ERROR_NO_MEMORY;
        }

        if (cJSON_AddItemToArray(expected_rules, json_rule_name) == 0) {
          cJSON_Delete(*json_map);
          yr_rules_destroy(rules);
          return YRRC_ERROR_NO_MEMORY;
        }
      }
    }
  }

  yr_rules_destroy(rules);
  return YRRC_NO_ERROR;
}
