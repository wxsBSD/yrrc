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
#include <sys/errno.h>

#include "error.h"
#include "utils.h"

int read_json_file(char* json_file, cJSON** json) {
  FILE* fp = NULL;
  long file_size = 0;
  size_t read_size = 0;
  char* contents = NULL;

  fp = fopen(json_file, "r");
  if (fp == NULL)
    return YRRC_ERROR_OPENING_FILE;

  if (fseek(fp, 0, SEEK_END) == -1) {
    fclose(fp);
    return YRRC_ERROR_OPENING_FILE;
  }

  file_size = ftell(fp);
  if (file_size == -1 || file_size == 0) {
    fclose(fp);
    return YRRC_ERROR_OPENING_FILE;
  }
  rewind(fp);

  contents = (char*)malloc(file_size);
  if (contents == NULL) {
    fclose(fp);
    return YRRC_ERROR_NO_MEMORY;
  }

  read_size = fread(contents, sizeof(char), file_size, fp);
  if (read_size != file_size) {
    free(contents);
    fclose(fp);
    return YRRC_ERROR_OPENING_FILE;
  }
  fclose(fp);

  *json = cJSON_Parse(contents);
  free(contents);
  if (*json == NULL)
    return YRRC_ERROR_INVALID_CONFIG;

  return YRRC_NO_ERROR;
}

int get_string_from_config(cJSON* config, char* key, char** value) {
  cJSON* config_obj = NULL;

  config_obj = cJSON_GetObjectItemCaseSensitive(config, key);
  if (config_obj == NULL)
    return YRRC_ERROR_INVALID_CONFIG;

  if (!cJSON_IsString(config_obj) || config_obj->valuestring == NULL)
    return YRRC_ERROR_INVALID_CONFIG;

  *value = config_obj->valuestring;
  return YRRC_NO_ERROR;
}

void compiler_callback(
    int error_level,
    const char* file_name,
    int line_number,
    const YR_RULE* rule,
    const char* message,
    void* user_data) {
  char* level;
  if (error_level == YARA_ERROR_LEVEL_ERROR) {
    level = "ERROR";
  } else {
    level = "WARNING";
  }

  printf("Compilation %s line %d: %s", level, line_number, message);
  if (rule != NULL) {
    printf("Rule: %s", rule->identifier);
  }
}

int compile_rules(char* rules_file, YR_RULES** rules) {
  YR_COMPILER* compiler = NULL;
  FILE* fp;

  fp = fopen(rules_file, "r");
  if (fp == NULL)
    return YRRC_ERROR_OPENING_FILE;

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
    fclose(fp);
    return YRRC_ERROR_RULE_COMPILATION;
  }

  yr_compiler_set_callback(compiler, compiler_callback, NULL);

  if (yr_compiler_add_file(compiler, fp, NULL, rules_file) != 0) {
    fclose(fp);
    yr_compiler_destroy(compiler);
    return YRRC_ERROR_RULE_COMPILATION;
  }
  fclose(fp);

  if (yr_compiler_get_rules(compiler, rules) != ERROR_SUCCESS) {
    yr_compiler_destroy(compiler);
    return YRRC_ERROR_RULE_COMPILATION;
  }

  yr_compiler_destroy(compiler);
  return YRRC_NO_ERROR;
}
