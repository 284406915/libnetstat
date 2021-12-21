#include <iostream>
#include "netstat.h"

using namespace std;

int main(int argc, char *argv[])
{
    cout << "Hello, World!" << endl;

    check_param cp;
    netstat_infos && infos = NetStat::GetInfo(cp);
    return 0;
}