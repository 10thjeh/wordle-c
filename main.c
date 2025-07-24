#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>  // You need to install the cJSON library

// Structure to store response data
struct MemoryStruct {
  char *memory;
  size_t size;
};

// Callback function to handle received data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
 
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(!ptr) {
    /* out of memory! */ 
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) { }
}

char* get_today_word(CURL *hnd, CURLcode *ret_code) {
    // Initialize the memory structure
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);  // will be grown as needed by realloc
    chunk.size = 0;    // no data at this point
    char *solution_word = NULL;
    
    curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(hnd, CURLOPT_URL, "https://www.nytimes.com/svc/wordle/v2/2025-07-24.json");
    curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(hnd, CURLOPT_USERAGENT, "curl/8.5.0");
    curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(hnd, CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(hnd, CURLOPT_FTP_SKIP_PASV_IP, 1L);
    curl_easy_setopt(hnd, CURLOPT_TCP_KEEPALIVE, 1L);
    
    // Set the write function callback and data pointer
    curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(hnd, CURLOPT_WRITEDATA, (void *)&chunk);
    
    // Fix 1: Use the handle directly, not its address
    *ret_code = curl_easy_perform(hnd);

    if(*ret_code == CURLE_OK) {
        // Now chunk.memory points to the response data
        printf("Response size: %lu bytes\n", (unsigned long)chunk.size);
        
        // Parse JSON response
        cJSON *json = cJSON_Parse(chunk.memory);
        if (json) {
            // Fix 2: Use a different variable name to avoid shadowing
            cJSON *solution_json = cJSON_GetObjectItemCaseSensitive(json, "solution");
            if (cJSON_IsString(solution_json) && (solution_json->valuestring != NULL)) {
                // Allocate memory for the return value
                solution_word = strdup(solution_json->valuestring);
            }
           
            cJSON_Delete(json);
        } else {
            const char *error_ptr = cJSON_GetErrorPtr();
            if (error_ptr != NULL) {
                printf("Error parsing JSON: %s\n", error_ptr);
            }
            printf("Failed to parse JSON\n");
        }
    } else {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(*ret_code));
    }

    free(chunk.memory);
    return solution_word;
}

int main()
{
    CURL *hnd;
    CURLcode ret;
    hnd = curl_easy_init();
    
    if(!hnd) {
        fprintf(stderr, "Failed to initialize CURL\n");
        return 1;
    }

    char *solution = get_today_word(hnd, &ret);
    if (solution) {
        printf("Today's Wordle solution: %s\n", solution);
        free(solution); // Don't forget to free the memory allocated by strdup
    } else {
        printf("Failed to retrieve today's Wordle solution.\n");
        return 1;
    }

    int isSolved = 0;
    int attemptCount = 0;
    while(!isSolved && attemptCount < 6) {
        char guess[60];
        printf("Enter your guess (5 letters): ");
        fgets(guess, sizeof(guess), stdin);
        // Remove the newline character
        int len = strlen(guess);
        if (len > 0 && guess[len-1] == '\n') {
            guess[len-1] = '\0';
            len--; // Adjust the length
        }
        clear_input_buffer(); // Clear the input buffer
        printf("You guessed: %s\n", guess);
        if (strlen(guess) != 5) {
            printf("Invalid guess. Please enter a 5-letter word.\n");
            printf("You entered %d characters.\n", (int)strlen(guess));
            continue;
        }
        
        // Check if the guess matches the solution
        printf("strcmp: %d\n", strcmp(guess, solution));
        if (strcmp(guess, solution) == 0) {
            printf("Congratulations! You've solved today's Wordle!\n");
            isSolved = 1;
        } else {
            printf("Incorrect guess. Try again.\n");
        }
    }
    
    curl_easy_cleanup(hnd);
    return 0;
}