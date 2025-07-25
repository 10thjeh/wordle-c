#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>  // You need to install the cJSON library

#define MAX_WORD_LENGTH 512
#define WORDLE_BASE_URL "https://www.nytimes.com/svc/wordle/v2/"

char* getInputString() {
    static char input[MAX_WORD_LENGTH];
    fgets(input, sizeof(input), stdin);
    
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
    }
    return input;
}

void clear_screen() {
    printf("\e[1;1H\e[2J"); // ANSI escape code to clear the screen
}


// Structure to store response data
struct MemoryStruct {
  char *memory;
  size_t size;
};

struct WordleResult {
    char *solution;
    char *date;
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

char* get_today_date() {
    //get the current date in YYYY-MM-DD format
    // Get the current date in YYYY-MM-DD format
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    static char date[16]; // Increased buffer size to be safe
    snprintf(date, sizeof(date), "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return date;
}

char* get_today_wordle_json() {
    // Get today's date in YYYY-MM-DD format
    char *date = get_today_date();
    
    // Construct the URL for today's Wordle
    static char url[MAX_WORD_LENGTH];
    snprintf(url, sizeof(url), "%s%s.json", WORDLE_BASE_URL, date);
    
    return url;
}

struct WordleResult get_today_word(CURL *hnd, CURLcode *ret_code) {
    // Initialize the memory structure
    struct MemoryStruct chunk;
    struct WordleResult result;
    chunk.memory = malloc(1);  // will be grown as needed by realloc
    chunk.size = 0;    // no data at this point
    result.solution = NULL;
    result.date = NULL;
    
    curl_easy_setopt(hnd, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(hnd, CURLOPT_URL, get_today_wordle_json());
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
        // Parse JSON response
        cJSON *json = cJSON_Parse(chunk.memory);
        if (json) {
            // Fix 2: Use a different variable name to avoid shadowing
            cJSON *solution_json = cJSON_GetObjectItemCaseSensitive(json, "solution");
            if (cJSON_IsString(solution_json) && (solution_json->valuestring != NULL)) {
                // Allocate memory for the return value
                printf("Today's Wordle solution is: %s\n", solution_json->valuestring);
                result.solution = strdup(solution_json->valuestring);
            }

            cJSON *date_json = cJSON_GetObjectItemCaseSensitive(json, "print_date");
            if (cJSON_IsString(date_json) && (date_json->valuestring != NULL)) {
                // Allocate memory for the date
                printf("Today's date is: %s\n", date_json->valuestring);
                result.date = strdup(date_json->valuestring);
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
    return result;
}

int main()
{
    clear_screen();
    CURL *hnd;
    CURLcode ret;
    hnd = curl_easy_init();
    
    if(!hnd) {
        fprintf(stderr, "Failed to initialize CURL\n");
        return 1;
    }

    struct WordleResult result = get_today_word(hnd, &ret);
    if (!result.solution) {
        printf("Failed to retrieve today's Wordle solution.\n");
        return 1;
    }

    int isSolved = 0;
    int attemptCount = 0;
    while(!isSolved && attemptCount < 6) {
        printf("Today is %s\n", get_today_date());
        printf("Welcome to Wordle-c - Today's Wordle is for %s\n", result.date);
        printf("Enter your guess (5 letters): ");
        char *guess = getInputString();

        if (strlen(guess) != 5) {
            printf("Invalid guess. Please enter a 5-letter word.\n");
            continue;
        }
        
        // Check if the guess matches the solution
        if (strcmp(guess, result.solution) == 0) {
            printf("Congratulations! You've solved today's Wordle!\n");
            isSolved = 1;
        } else {
            printf("Incorrect guess. Try again.\n");
        }
    }
    
    curl_easy_cleanup(hnd);
    free(result.solution); // Don't forget to free the memory allocated by strdup
    free(result.date);
    return 0;
}