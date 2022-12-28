#include <iostream>
#include <chrono>

using ll = uint64_t;
static const ll seed = std::chrono::steady_clock::now().time_since_epoch().count();
ll seed_ = 0xdeadbeef69420;
static constexpr uint32_t pp = 7;// require that pp be a prime less than 2^32 so squaring doesn't overflow uint64_t

// splitmix64 hash function as pseudorandom generator with current time as seed
ll splitmix64(ll input){
    ll x = input + seed;
    x += 0x9e3779b97f4a7c15;
    x = (x^(x>>30))*0xbf58476d1ce4e5b9;
    x = (x^(x>>27))*0x94d049bb133111eb;
    return x^(x>>31);
}

// returns g^x (mod p)
ll exp(ll g, ll x, uint32_t p){
    x %= p, g %= p;
    if(x==0) return 1;
    else if(x==1) return g;
    else if(const ll sub = exp(g, x>>1, p); true) return ((x&1 ? g : 1)*(sub*sub)%p)%p;
}

// non-interactive zero-knowledge proof for discrete log
std::pair<ll,ll> dlogProof(ll x, ll g, uint32_t p){
    ll a = (seed_ = splitmix64(seed_))%p;
    ll t = exp(g, a, p);
    ll c = splitmix64(g + exp(g, x, p) + t)%p;
    ll r = (a+((p-1)*(p-1) - c*x)%(p-1))%(p-1);// because fucky c++ modding
    std::cout << "prover: " << c << " " << t << " r: " << r << std::endl;
    return {t, r};
}

// verification algorithm to test that dlogProof truly knows x given g^x, p
bool verify(ll y, ll g, uint32_t p, std::pair<ll,ll> pf){
    ll c = splitmix64(g + y + (pf.first))%p;
    std::cout << "verifier: " << c << " " << pf.first << " " << exp(y, c, p) << " " << exp(g, pf.second, p) << " " << y << std::endl;
    std::cout << pf.first << " " << (exp(y, c, p)*exp(g, pf.second, p))%p << std::endl;
    return (pf.first) == (exp(y, c, p)*exp(g, pf.second, p))%p;
}

// repeat verification k times to decrease completeness error from 1/2 to 2^-k
bool rep(ll x, ll y, ll g, uint32_t p, int k){
    while(k--) if(!verify(y, g, p, dlogProof(x, g, p))) return false;
    return true;
}

int main(){
    ll g, x, y;
    std::cin >> g >> x;
    y = exp(g, x, pp);
    std::cout << "inputs: " << g << " " << x << " " << y << std::endl;
    std::cout << rep(x, y, g, pp, 1) << std::endl;
}
