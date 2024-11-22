#include <iostream>
// #include "bpf_sockops.h"

using namespace std;
static const unsigned int podsubnet_s = (10 << 24) + (244 << 16);
static const unsigned int podsubnet_e = (10 << 24) + (244 << 16) + (255 << 8) + (255);


static const unsigned int podsubnet_t1 = (10) + (244 << 8) + (123 << 16) + (111 << 24);
static const unsigned int podsubnet_t2 = (10 << 24) + (244 << 16) + (255 << 8) + (255);


int main(){
    // cout<<podsubnet_s<<" "<<podsubnet_e<<endl;

    // cout<<"host ip:"<<endl;
    // cout<<__builtin_bswap32((podsubnet_s))<<" "<<__builtin_bswap32((podsubnet_e))<<endl;
    cout<<podsubnet_t1<<endl;
    cout<< ((podsubnet_t1 << 24) >> 24) <<" "<< ((podsubnet_t1 << 16) >> 16) <<endl;

    return 0;
}