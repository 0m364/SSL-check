#include <iostream>
#include <sstream>
#include <string>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Callback function to write received data
size_t WriteCallback(char* ptr, size_t size, size_t nmemb, std::string* data)
{
    data->append(ptr, size * nmemb);
    return size * nmemb;
}

// Function to check if the site is dangerous
bool isSiteDangerous(const std::string& url)
{
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Create a curl handle
    CURL* curl = curl_easy_init();
    if (!curl)
    {
        std::cerr << "Failed to initialize curl" << std::endl;
        return false;
    }

    // Set the URL to check
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

    // Set the SSL certificate verification
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");

    // Set the data write callback
    std::string content;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &content);

    // Perform the HTTP request
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        std::cerr << "Failed to fetch the website content: " << curl_easy_strerror(res) << std::endl;
        curl_easy_cleanup(curl);
        return false;
    }

    // Check the SSL certificate verification result
    SSL* ssl = nullptr;
    if (curl_easy_getinfo(curl, CURLINFO_TLS_SSL_PTR, &ssl) == CURLE_OK)
    {
        long verifyresult = SSL_get_verify_result(ssl);
        if (verifyresult != X509_V_OK)
        {
            std::cerr << "SSL certificate verification failed: " << X509_verify_cert_error_string(verifyresult) << std::endl;
            curl_easy_cleanup(curl);
            return false;
        }
    }

    // Scrape website content and determine if it is dangerous (customize this part as per your definition of dangerous)
    bool isDangerous = (content.find("dangerous_keyword") != std::string::npos);

    // Clean up
    curl_easy_cleanup(curl);

    // Cleanup SSL resources
    if (ssl)
        ERR_remove_thread_state(nullptr);

    // Cleanup curl resources
    curl_global_cleanup();

    return isDangerous;
}

int main()
{
    std::string url = "https://example.com";  // URL to check

    bool isDangerous = isSiteDangerous(url);
    if (isDangerous)
    {
        std::cout << "The site is potentially dangerous." << std::endl;
    }
    else
    {
        std::cout << "The site is safe." << std::endl;
    }

    return 0;
}
