#include "filter.h"

Filter::Filter()
{

}

Filter::~Filter()
{

}

/*
 * usage of commands
 * [-options] [data] ...
 * -p protocol / -s sourceIP / -d destinationIP / -sport sourcePort / -dport destinationPort
 * using regex to check syntax.
 */
bool Filter::checkCommand(QString command)
{
    //LOG(command.toLatin1().data());
    std::string pattern{ "([ ]*((-p[ ]+[a-zA-Z]+)|((-s|-d)[ ]+\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})|((-sport|-dport)[ ]+\\d+))[ ]+)*((-p[ ]+[a-zA-Z]+)|((-s|-d)[ ]+\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3})|((-sport|-dport)[ ]+\\d+))?" };
    std::regex re(pattern);
    return std::regex_match(command.toStdString(), re);
}

/*
 * load correct command to query structure
 * preparation for function launchFilter.
 */
bool Filter::loadCommand(QString command)
{
    //LOG(command.toLatin1().data());
    query.clear();
    if (! checkCommand(command)) {
        return false;
    }
    std::string com = command.toStdString();
    std::size_t pos;
    pos = com.find("-p");
    if (pos<com.size()) query.insert(make_pair(P, findWord(com, pos+2)));
    pos = com.find("-s");
    if (pos<com.size()) query.insert(make_pair(S, findWord(com, pos+2)));
    pos = com.find("-d");
    if (pos<com.size()) query.insert(make_pair(D, findWord(com, pos+2)));
    pos = com.find("-sport");
    if (pos<com.size()) query.insert(make_pair(SPORT, findWord(com, pos+5)));
    pos = com.find("-dport");
    if (pos<com.size()) query.insert(make_pair(DPORT, findWord(com, pos+5)));
    return true;
}

string Filter::findWord(string com, size_t pos)
{
    size_t beg = com.find_first_not_of(string(" "), pos);
    size_t end = com.find_first_of(string(" "), beg);
    if (end >= com.size()) end = com.find_first_of(string("\n"), beg);

    return com.substr(beg, end-beg);
}

void Filter::launchFilter(MultiView *view)
{
    //clear the tableView
    view->rebuildInfo();
    bool flag;
    //filtrate every packet
    for(std::vector<SnifferData>::iterator iSnifferData = view->packets.begin(); iSnifferData<view->packets.end(); iSnifferData++) {
        flag = true;
        for(std::map<int, std::string>::iterator iQuery = query.begin(); iQuery!=query.end(); iQuery++) {
            switch(iQuery->first) {
            case(P):{
                if (iSnifferData->strProto.toStdString().find(iQuery->second.data()) > iSnifferData->strProto.toStdString().length()) {
                    flag = false;
                }
                break;
            }
            case(S):{
                std::string tmpSource = iSnifferData->strSIP.toStdString();
                tmpSource = tmpSource.substr(0,tmpSource.find_first_of(':'));
                if (iQuery->second.find(tmpSource.data()) !=0) {
                    flag = false;
                }
                break;
            }
            case(D):{
                std::string tmpDes = iSnifferData->strDIP.toStdString();
                tmpDes = tmpDes.substr(0,tmpDes.find_first_of(':'));
                if (iQuery->second.find(tmpDes.data()) != 0) {
                    flag = false;
                }
                break;
            }
            case(SPORT):{
                std::string tmpSPort = iSnifferData->strSIP.toStdString();
                tmpSPort = tmpSPort.substr(tmpSPort.find_first_of(':'));
                if(iQuery->second.find(tmpSPort.data()) != 0) {
                    flag = false;
                }
                break;
            }
            case(DPORT):{
                std::string tmpDPort = iSnifferData->strDIP.toStdString();
                tmpDPort = tmpDPort.substr(tmpDPort.find_first_of(':'));
                if(iQuery->second.find(tmpDPort.data()) != 0) {
                    flag = false;
                }
                break;
            }
            }
            if (!flag) break;
        }
        //add the item to TableView if packet matched
        if (flag) view->addPacketItem(*iSnifferData, false);
    }
}


void Filter::printQuery()
{
    LOG("test mode");
    for(std::map<int, std::string>::iterator iQuery = query.begin(); iQuery!=query.end(); iQuery++) {
        std::cout<<iQuery->first<<"  "<<iQuery->second.data()<<endl;
    }
}
