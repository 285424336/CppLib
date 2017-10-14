#ifndef FINGER_PRINT_DB__H_INCLUDED
#define FINGER_PRINT_DB__H_INCLUDED

#include <vector>
#include <string>
#include <algorithm>
#include <memory>
#include <string.h>

/* Maximum number of results allowed in one of these things ... */
#define MAX_FP_RESULTS 36
#define OSSCAN_GUESS_THRESHOLD 0.85
#define OSSCAN_SUCCESS 0
#define OSSCAN_NOMATCHES -1
#define OSSCAN_TOOMANYMATCHES -2

class OSClassification
{
    /**
    *store line: Class 2N | embedded | | specialized
    *store line: CPE cpe:/h:2n:helios
    */
public:
    const char * OS_Vendor;
    const char * OS_Family;
    const char * OS_Generation; /* Can be empty if unclassified */
    const char * Device_Type;
    std::vector<const char *> cpe;

    OSClassification() :OS_Vendor(NULL), OS_Family(NULL), OS_Generation(NULL), Device_Type(NULL), cpe()
    {

    }
};

class FingerMatch
{
    /**
    *A description of an operating system: a human-readable name and a list ofclassifications.
    */
public:
    const char *os_name; //store line: Fingerprint 2N Helios IP VoIP doorbell
    std::vector<OSClassification> os_class;

    FingerMatch() :os_name(NULL), os_class()
    {

    }
};

class AVal
{
    /**
    *store info SP=0-5 of line: SEQ(SP=0-5%GCD=51E80C|A3D018|F5B824|147A030|199883C%ISR=C8-D2%TI=I|RD%CI=I%II=RI%SS=S%TS=U)
    */
public:
    const char *attribute;//like SP
    const char *value;//like 0-5

    AVal() :attribute(NULL), value(NULL)
    {
    }

    bool operator<(const AVal& other) const
    {
        if (!this->attribute) {
            //empty to vetor end
            return false;
        }
        if (!other.attribute) {
            //empty to vetor end
            return true;
        }
        return strcmp(this->attribute, other.attribute) < 0;
    }
};

/**
store singile test line like T4(R=Y%DF=Y%T=FA-104%TG=FF%W=0%S=A%A=Z%F=R%O=%RD=E44A4E43%Q=)
*/
class FingerTest
{
public:
    const char *name;
    std::vector<AVal> results;

    FingerTest() :name(NULL), results()
    {

    }

    bool operator<(const FingerTest& other) const
    {
        if (!this->name) {
            //empty to vetor end
            return false;
        }
        if (!other.name) {
            //empty to vetor end
            return true;
        }
        return strcmp(this->name, other.name) < 0;
    }

    std::string str()
    {
        std::string r;

        if (!name) {
            return r;
        }
        r += name;
        r += "(";
        
        for (auto av = results.begin(); av != results.end(); av++) {
            if (av != results.begin()) {
                r += '%';
            }
            if (av->attribute) {
                r += av->attribute;
                r += "=";
                if (av->value) {
                    r += av->value;
                }
            }
        }
        r += ")";
        return r;
    }
};

class FingerPrint
{
    /**
    *in DB it used to store match info 
    *and when match it used to store the user
    */
public:
    std::shared_ptr<FingerMatch> match;//what need to show
    std::vector<FingerTest> tests;//test record when success show match info

    FingerPrint()
    {
        match = std::make_shared<FingerMatch>();
    }

    void sort()
    {
        for (size_t i = 0; i < tests.size(); i++) {
            std::stable_sort(tests[i].results.begin(), tests[i].results.end());
        }
        std::stable_sort(tests.begin(), tests.end());
    }

    std::string str()
    {
        std::string r;
        for (auto test = tests.begin(); test != tests.end(); test++) {
            r += test->str() + "\n";
        }
        return r;
    }
};

class FingerPrintResults;
class FingerPrintDB
{
private:
    FingerPrint MatchPoints;//store line MatchPoints, which used to calculate the weigth
    std::vector<FingerPrint> prints;//stroe line FingerPrint

public:
    /**
    *init fb from file
    */
    bool InitFromFile(const std::string &file);
    /**
    *init fb from content
    */
    bool InitFromContent(const std::string &content);
    FingerPrintResults MatchFingerprint(const FingerPrint &fp, double accuracy_threshold = OSSCAN_GUESS_THRESHOLD);

private:
    double CompareFingerprints(const FingerPrint &referenceFP, const FingerPrint &observedFP);
    int AValMatch(const FingerTest &reference, const FingerTest &fprint, const FingerTest &points,
        unsigned long *num_subtests, unsigned long *num_subtests_succeeded);
    bool ExprMatch(const char *val, const char *expr);
};

class OSClassificationResults {
public:
    std::vector<std::pair<double, OSClassification>> osc;
    int osc_num_perfect_matches; // Number of perfect matches in OSC[\]
    int overall_results; /* OSSCAN_TOOMANYMATCHES, OSSCAN_NOMATCHES, OSSCAN_SUCCESS, etc */

    OSClassificationResults() :overall_results(OSSCAN_NOMATCHES), osc_num_perfect_matches(0), osc()
    {

    }

    std::string str(bool guess);

private:
    int AddToCharArrayIfNew(const char *arr[], int *numentries, int arrsize, const char *candidate);
};

class FingerPrintResults 
{
    /**
    *store the result of match
    */
public:
    static bool strnulleq(const char *s, const char *t);

public:
    std::vector<std::pair<double, std::shared_ptr<FingerMatch>>> matches;/* first element Percentage of match (1.0 == perfect match), it is sort from high to low
                                                                         second element point to matching references highest accuracy matches first */
    int num_perfect_matches; /* count of 1.0 accuracy matches in matches[] */
    int overall_results; /* OSSCAN_TOOMANYMATCHES, OSSCAN_NOMATCHES, OSSCAN_SUCCESS, etc */
    std::shared_ptr<FingerPrint> fp; /* finger print of the device*/

public:
    FingerPrintResults() :overall_results(OSSCAN_NOMATCHES), num_perfect_matches(0), matches()
    {

    }
    virtual ~FingerPrintResults()
    {

    }
    std::string str(bool guess=true);
    /* Ensures that the results are available and then returns them.
    You should only call this AFTER all matching has been completed
    (because results are cached and won't change if new matches[] are
    added.)  All OS Classes in the results will be unique, and if there
    are any perfect (accuracy 1.0) matches, only those will be
    returned */
    OSClassificationResults GetOSClassification();
};

#endif
