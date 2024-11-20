#include <iostream>
using namespace std;

static const unsigned int podsubnet_s = 10 + (20 << 8);
static const unsigned int podsubnet_e = 10 + (20 << 8) + (255 << 16) + (255 << 24);

static const unsigned int podsubnet_other = 11 + (20 << 8) + (255 << 16);

int main(){
    cout<<podsubnet_s<<" "<<podsubnet_e<<endl;
    cout<<podsubnet_other<<endl;
    return 0;
}