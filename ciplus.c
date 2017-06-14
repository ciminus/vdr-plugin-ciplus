/*
 * ciplus.c: A plugin for the Video Disk Recorder
 *
 * See the README file for copyright information and how to reach the author.
 *
 * $Id$
 */

#if defined(APIVERSNUM) && APIVERSNUM < 20305
    #error "VDR-2.3.5 API version or greater is required!"
#endif

#include <vdr/plugin.h>
#include <vdr/ci.h>
#include <getopt.h>
#include "cCiPlusResourceHandler.h"
#include "cCiPlusPrivate.h"

#include "ciplus.h"

#define LIBCIPLUSPRIVATE PLUGINDIR "/libciplusprivate.so"

static const char *VERSION        = "1.0.1";
static const char *DESCRIPTION    = "Use CI+ Modules with VDR";

const char *confDir = NULL;
const char *cacheDir = NULL;
bool DebugProtocol = false;

class cPluginCiplus : public cPlugin {
private:
    cString privateDataLibName;
    cCiPlusPrivate *privateData;
public:
  cPluginCiplus(void);
  virtual ~cPluginCiplus();
  virtual const char *Version(void) { return VERSION; }
  virtual const char *Description(void) { return DESCRIPTION; }
  virtual const char *CommandLineHelp(void);
  virtual bool ProcessArgs(int argc, char *argv[]);
  virtual bool Initialize(void);
  
  };

cPluginCiplus::cPluginCiplus(void)
{
    privateDataLibName = NULL;
    privateData = new cCiPlusPrivate;
}

cPluginCiplus::~cPluginCiplus()
{
    delete privateData;
}

const char *cPluginCiplus::CommandLineHelp(void)
{
    const char *help = "  -d                       Enable Debug-Output on stderr\n"
                       "  -l <privateDataLibName>      File name (with path) of CI+ private data library\n";
    return help;
}

bool cPluginCiplus::ProcessArgs(int argc, char *argv[])
{
    int c;
    opterr = 0;
    while ((c = getopt (argc, argv, "dl:")) != -1) {
        switch(c) {
            case 'd': DebugProtocol = true; break;
            case 'l': privateDataLibName = optarg; break;
        }
    }
    return true;
}

bool cPluginCiplus::Initialize(void)
{
    confDir = ConfigDirectory(Name());
    cacheDir = CacheDirectory(Name());
    if(!(const char *)privateDataLibName) {
        privateDataLibName = LIBCIPLUSPRIVATE;
    }
        
    if(privateData->LoadPrivateData((const char *)privateDataLibName)) {
        CiResourceHandlers.Register(new cCiPlusResourceHandler(privateData));
    } else {
        esyslog("ciplus: Can't load CI+ private data. CI+ disabled!");
    }
    return true;
}


VDRPLUGINCREATOR(cPluginCiplus); // Don't touch this!
