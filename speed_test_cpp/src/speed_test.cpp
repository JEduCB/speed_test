#include <algorithm>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <vector>

extern "C"
{
#include "../include/speed_test_lib.h"
}

using namespace std;

typedef unordered_map<string, int> Args;

static vector<int> rsa_keys = {512, 1024, 2048, 3072, 4096, 7680, 15360};

const static string _async_jobs{"async_jobs"};
const static string _seconds{"seconds"};
const static string _rsa{"rsa"};

bool parse_args(int argc, char *argv[], Args& args)
{
    if(argc == 1 || argc != 4) return false;

    for(int i = 1; i < argc; ++i)
    {
        string arg{argv[i]};
        string key{};
        int value{0};

        if(arg.substr(0, 3) == _rsa)
        {
            try
            {
                value = stoi(arg.substr(3));

                if(find(rsa_keys.begin(), rsa_keys.end(), value) == rsa_keys.end()) return false;

                args[_rsa] = value;
            }
            catch(...)
            {
                return false;
            }
        }
        else
        {
            auto equal_sign{arg.find('=')};

            if(equal_sign == string::npos) return false;

            key = arg.substr(0, equal_sign);
            
            try
            {
                value = stoi(arg.substr(equal_sign + 1));

                if(value < 0) return false;
            }
            catch(...)
            {
                return false;
            }

            if(key != _async_jobs && key != _seconds) return false;

            if(key == _async_jobs && value > 99999) return false;

            args[key] = value;        
        }
    }

    return true;
}

int main(int argc, char *argv[])
{
    Args args;

    if(!parse_args(argc, argv, args))
    {
        printf("Usage:\n");
        printf("\tspeed_test %s=num_jobs %s=time_in_seconds %s[bits]\n\n", _async_jobs.c_str(), _seconds.c_str(), _rsa.c_str());
        printf("\tnum_jobs\t-> [0-99999] - Enable async mode and start specified number of jobs. Use 0 for running in sync mode\n");
        printf("\ttime_in_seconds\t-> Run the test for specified amount of seconds.\n");
        printf("\tbits\t\t-> [");

        for(auto bits: rsa_keys) printf("%d, ", bits);

        printf("\b\b]\n\n");
        exit(-1);
    }

    string cipher_name = {_rsa + to_string(args[_rsa])};

    run_speed_test(args[_async_jobs], args[_seconds], args[_rsa], cipher_name.c_str());
}
