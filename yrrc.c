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

#include <getopt.h>
#include <stdlib.h>

#include "cJSON.h"
#include "collect.h"
#include "scan.h"
#include "error.h"
#include "utils.h"
#include "yara.h"

#define MODE_COLLECT "collect"
#define MODE_SCAN "scan"

void usage(void) {
  printf("\nUsage:\n");
  printf("-c <config file>\n");
  printf("-m <collect|scan>\n");
  return;
}

int main(int argc, char* argv[]) {
  int result = YRRC_NO_ERROR;
  int ch = 0;
  int collect = 0;
  int scan = 0;
  char* config_file = NULL;
  char* mode = NULL;
  const char* error_ptr = NULL;
  cJSON* config = NULL;
  cJSON* json = NULL;

  if (argc == 1) {
    printf("%s -c <config file> -m <collect|scan>\n", argv[0]);
    usage();
    return EXIT_FAILURE;
  }

  while ((ch = getopt(argc, argv, "c:hm:")) != -1) {
    switch (ch) {
      case 'h':
        usage();
        return EXIT_SUCCESS;
      case 'c':
        config_file = optarg;
        break;
      case 'm':
        mode = optarg;
        break;
      default:
        printf("Unknown option %c\n", optopt);
        usage();
        return EXIT_FAILURE;
    }
  }

  if (config_file == NULL) {
    printf("Must provide a config file.\n");
    return EXIT_FAILURE;
  }

  if (strcmp(mode, MODE_COLLECT) == 0)
    collect = 1;
  else if (strcmp(mode, MODE_SCAN) == 0)
    scan = 1;
  else {
    printf("Unknown mode.\n");
    usage();
    return EXIT_FAILURE;
  }

  result = read_json_file(config_file, &config);
  if (result != YRRC_NO_ERROR) {
    printf("Config error: %d\n", result);
    error_ptr = cJSON_GetErrorPtr();
    if (error_ptr != NULL)
      printf("Error before: %s\n", error_ptr);
    return EXIT_FAILURE;
  }

  yr_initialize();
  if (collect)
    result = collect_hashes(config, &json);
  else if (scan)
    result = scan_files(config, &json);
  yr_finalize();

  if (result != YRRC_NO_ERROR) {
    printf("Error performing action: %d.\n", result);
    cJSON_Delete(config);
    return EXIT_FAILURE;
  }

  printf("%s\n", cJSON_Print(json));
  cJSON_Delete(json);
  cJSON_Delete(config);

  return YRRC_NO_ERROR;
}
