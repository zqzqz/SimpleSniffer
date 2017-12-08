#ifndef LOG_H
#define LOG_H
#include <iostream>
#define LOG(msg) std::cout<<"("<<__FILE__<<":"<<__LINE__<<")"<<msg<<std::endl;
#endif // LOG_H
