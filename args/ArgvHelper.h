/*
  Copyright (c) 2009, Hideyuki Tanaka
  All rights reserved.
  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:
  * Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.
  * Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.
  * Neither the name of the <organization> nor the
  names of its contributors may be used to endorse or promote products
  derived from this software without specific prior written permission.
  THIS SOFTWARE IS PROVIDED BY <copyright holder> ''AS IS'' AND ANY
  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL <copyright holder> BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef ARGV_HELPER_H_INCLUDED
#define ARGV_HELPER_H_INCLUDED

#include <iostream>
#include <sstream>
#include <vector>
#include <set>
#include <map>
#include <string>
#include <stdexcept>
#include <typeinfo>
#include <cstring>
#include <algorithm>
#include <cstdlib>

#if defined(_MSC_VER)
#ifndef THROW
#define THROW(x) throw(...)
#endif // !THROW
#elif defined(__GNUC__)
#ifndef THROW
#define THROW(x) throw(x)
#endif // !THROW
#define _CONSOLE
#else
#error unsupported compiler
#endif

namespace ArgvHelper {
    using namespace std;

    template<typename T>
    struct is_container : public false_type
    {
        typedef T type;
    };

    template<typename T>
    struct is_container<set<T>> : public true_type
    {
        typedef T type;
        typedef set<T> contain_type;
    };

    template<typename T>
    struct is_container<vector<T>> : public true_type
    {
        typedef T type;
        typedef vector<T> contain_type;
    };

    template <typename T1, typename T2>
    struct is_same : public false_type {
    };

    template <typename T>
    struct is_same<T, T> : public true_type {
    };

    // TEMPLATE CLASS is_signed
    template<class _Ty1>
    struct _is_signed
        : std::false_type
    {	// determine whether _Ty1 is signed type
    };

    // TEMPLATE CLASS is_signed
    template<class _Ty1>
    struct is_signed : _is_signed<typename std::remove_cv<_Ty1>::type>
    {

    };

    template<>
    struct _is_signed<bool>
        : std::false_type
    {	// determine whether _Ty1 is signed type
    };

    template<>
    struct _is_signed<char>
        : std::true_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<unsigned char>
        : std::false_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<wchar_t>
        : std::false_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<signed short>
        : std::true_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<unsigned short>
        : std::false_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<char16_t>
        : std::false_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<signed int>
        : std::true_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<unsigned int>
        : std::false_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<char32_t>
        : std::true_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<signed long>
        : std::true_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<unsigned long>
        : std::false_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<long long>
        : std::true_type
    {	// determine whether _Ty is signed type
    };

    template<>
    struct _is_signed<unsigned long long>
        : std::false_type
    {	// determine whether _Ty is signed type
    };

    template <typename Target, typename Source, bool Same, bool SrcIsContainer>
    class _lexical_cast
    {
    public:
        static Target cast(const Source &arg)
        {
            Target ret;
            std::stringstream ss;
            if (std::is_integral<Target>::value && !is_signed<Target>::value && ss.str().size() > 1 && ss.str()[0] == '-') throw std::bad_cast();
            if (!(ss >> ret && ss.eof() && !ss.fail())) throw std::bad_cast();
            return ret;
        }
    };

    template <typename Target, typename Source>
    class _lexical_cast<Target, Source, true, false>
    {
    public:
        static Target cast(const Source &arg)
        {
            return arg;
        }
    };

    template <typename Source>
    class _lexical_cast<std::string, Source, false, false>
    {
    public:
        static std::string cast(const Source &arg)
        {
            std::ostringstream ss;
            ss << arg;
            return ss.str();
        }
    };

    template <typename Target>
    class _lexical_cast<Target, std::string, false, false>
    {
    public:
        static Target cast(const std::string &arg)
        {
            Target ret;
            std::istringstream ss(arg);
            if (std::is_integral<Target>::value && !is_signed<Target>::value && ss.str().size() > 1 && ss.str()[0] == '-') throw std::bad_cast();
            if (!(ss >> ret && ss.eof() && !ss.fail())) throw std::bad_cast();
            return ret;
        }
    };

    template <typename Source>
    class _lexical_cast<std::string, Source, false, true> 
    {
    public:
        typedef typename is_container<Source>::type type;

        static std::string cast(const Source &arg) 
        {
            std::ostringstream ss;
            for (auto s : arg)
            {
                ss << _lexical_cast<std::string, type, is_same<std::string, type>::value, is_container<type>::value>::cast(s) << " ";
            }
            return ss.str();
        }
    };

    /**
    *convert string to other type
    *Target: the type you want to convert to
    *Source: the type you want to be converted, it can be every type that can use operator <<
    *src: the source to be converted
    */
    template<typename Target, typename Source>
    Target lexical_cast(const Source &src)
    {
        if (std::is_same<typename std::remove_cv<Target>::type, char>::value)
        {
            short ret = _lexical_cast<short, typename std::remove_cv<Source>::type
                , std::is_same<char, typename std::remove_cv<Source>::type>::value, false>::cast(src);
            if (ret > 127 || ret < -128) throw std::bad_cast();
            return *(Target*)&ret;
        }
        else if (std::is_same<typename std::remove_cv<Target>::type, unsigned char>::value)
        {
            unsigned short ret = _lexical_cast<unsigned short, typename std::remove_cv<Source>::type
                , std::is_same<unsigned char, typename std::remove_cv<Source>::type>::value, false>::cast(src);
            if (ret > 255) throw std::bad_cast();
            return *(Target*)&ret;
        }
        else
        {
            return _lexical_cast<Target, Source, is_same<Target, Source>::value, is_container<Source>::value>::cast(src);
        }
    }

    /**
    *get the friendly type name, for example demangle(typeid(int).name())
    *name(in): type name
    */
    std::string demangle(const std::string &name);

    template <class T, bool Is_Container>
    struct readable_typename
    {
        static std::string name()
        {
            return demangle(typeid(T).name());
        }
    };

    template <class T>
    struct readable_typename<T, true>
    {
        static std::string name()
        {
            return readable_typename<typename is_container<T>::type, is_container<T>::value>::name() + "s";
        }
    };

    template <>
    struct readable_typename<std::string, false>
    {
        static std::string name()
        {
            return "string";
        }
    };

    class cmdline_error : public std::exception {
    public:
        cmdline_error(const std::string &msg) : msg(msg) {}
        ~cmdline_error() throw() {}
        const char *what() const throw() { return msg.c_str(); }
    private:
        std::string msg;
    };

    template <class T>
    struct default_reader {
        T operator()(const std::string &str) {
            return lexical_cast<T>(str);
        }
    };

    template <class T>
    struct range_reader {
        range_reader(const T &low, const T &high) : low(low), high(high) {}
        T operator()(const std::string &s) {
            T ret = default_reader<T>()(s);
            if (!(ret >= low && ret <= high)) throw cmdline_error("should in range:" + range());
            return ret;
        }
        std::string range()
        {
            std::ostringstream ss;
            ss << "[" << low << "-" << high << "]";
            return ss.str();
        }
    private:
        T low, high;
    };

    template <class T>
    struct oneof_reader {
        template <class ... T1>
        oneof_reader(T1 ...a1)
        {
            int arr[] = { (alt.push_back(a1), 0)... };
        }

        T operator()(const std::string &s) {
            T ret = default_reader<T>()(s);
            if (std::find(alt.begin(), alt.end(), ret) == alt.end())
                throw cmdline_error("should be one of:" + all_opt_value());
            return ret;
        }

        std::string all_opt_value()
        {
            std::ostringstream ss;
            ss << endl;
            for (decltype(alt.size()) i = 0; i < alt.size(); i++)
            {
                ss << " " << alt[i];
                if (i != alt.size() - 1)  ss << endl;
            }
            return ss.str();
        }
    private:
        std::vector<T> alt;
    };

    template <class T>
    struct contain_reader {
        T operator()(const std::string &s) = delete;
    };

    template <class T>
    struct contain_reader<set<T>> {
        set<T> operator()(const std::string &s) {
            if (m_max_count == -1 || m_max_count > all.size()) all.insert(default_reader<T>()(s));
            return all;
        }
        contain_reader(unsigned int max_count = -1) : m_max_count(max_count){}
    private:
        set<T> all;
        unsigned int  m_max_count;
    };

    template <class T>
    struct contain_reader<vector<T>> {
        vector<T> operator()(const std::string &s) {
            if (m_max_count == -1 || m_max_count > all.size()) all.push_back(default_reader<T>()(s));
            return all;
        }
        contain_reader(unsigned int max_count = -1) : m_max_count(max_count) {}
    private:
        vector<T> all;
        unsigned int  m_max_count;
    };

    class parser {
    public:
        parser() {}
        ~parser() {
            for (std::map<std::string, option_base*>::iterator p = options.begin();
                p != options.end(); p++)
                delete p->second;
        }

        /**
        *add a option flag that should not have value
        *name(in): long name, should be use with --
        *short_name(in): short name, should be use with -
        *desc(in): description of the flag, which will show in useage
        *need(in): is this flag must, if set true, and use do not input, parse will set errors
        */
        void add(const std::string &name,
            char short_name = 0,
            const std::string &desc = "",
            bool need = false) {
            if (options.count(name)) throw cmdline_error("multiple definition: " + name);
            options[name] = new option_without_value(name, short_name, desc, need);
            ordered.push_back(options[name]);
        }

        /**
        *add a option flag that should have value
        *name(in): long name, should be use with --
        *short_name(in): short name, should be use with -
        *desc(in): description of the flag, which will show in useage
        *need(in): is this flag must, if set true, and use do not input, parse will set errors
        *def(in): the default value
        *reader(in): the reader, you can use default_reader(defalut), range_reader(use for check number range), 
            oneof_reader(use for check one of), contain_reader(use for a range of value, type should be std::set or std::vector)
        */
        template <class T, class F = default_reader<T>>
        void add(const std::string &name,
            char short_name = 0,
            const std::string &desc = "",
            bool need = false,
            const T def = T(),
            F reader = F()) {
            if (options.count(name)) throw cmdline_error("multiple definition: " + name);
            options[name] = new option_with_value_with_reader<T, F>(name, short_name, need, def, desc, reader);
            ordered.push_back(options[name]);
        }

        /**
        *add the footer which will show in usage, do not influence parse
        *f(in): footer string
        */
        void footer(const std::string &f) {
            ftr = f;
        }

        /**
        *add the program name which will show in usage, do not influence parse
        *name(in): program string
        */
        void set_program_name(const std::string &name) {
            prog_name = name;
        }

        /**
        *check if user input the option flag
        *name(in): need to check flag name
        *return: if user input, then return true, otherwise return false
        */
        bool exist(const std::string &name) const {
            if (options.count(name) == 0) throw cmdline_error("there is no flag: --" + name);
            return options.find(name)->second->has_set();
        }

        template <class T>
        /**
        *get the option value
        *name(in): long option name
        */
        const T &get(const std::string &name) const {
            if (options.count(name) == 0) throw cmdline_error("there is no flag: --" + name);
            const option_with_value<T> *p = dynamic_cast<const option_with_value<T>*>(options.find(name)->second);
            if (p == NULL) throw cmdline_error("type mismatch flag '" + name + "'");
            return p->get();
        }

        /**
        *get the rest values which input not follow the option
        *name(in): long option name
        */
        const std::vector<std::string> &rest() const {
            return others;
        }

        /**
        *parse the args cmd string
        */
        bool parse(const std::string &arg) {
            std::vector<std::string> args;

            std::string buf;
            bool in_quote = false;
            for (std::string::size_type i = 0; i < arg.length(); i++) {
                if (arg[i] == '\"') {
                    in_quote = !in_quote;
                    continue;
                }

                if (arg[i] == ' ' && !in_quote) {
                    args.push_back(buf);
                    buf = "";
                    continue;
                }

                if (arg[i] == '\\') {
                    i++;
                    if (i >= arg.length()) {
                        errors.push_back("unexpected occurrence of '\\' at end of string");
                        return false;
                    }
                }

                buf += arg[i];
            }

            if (in_quote) {
                errors.push_back("quote is not closed");
                return false;
            }

            if (buf.length() > 0)
                args.push_back(buf);

            for (size_t i = 0; i < args.size(); i++)
#ifdef _CONSOLE
                std::cout << "\"" << args[i] << "\"" << std::endl;
#endif
            return parse(args);
        }

        /**
        *parse the args
        */
        bool parse(const std::vector<std::string> &args) {
            int argc = static_cast<int>(args.size());
            std::vector<const char*> argv(argc);

            for (int i = 0; i < argc; i++)
                argv[i] = args[i].c_str();

            return parse(argc, &argv[0]);
        }

        /**
        *parse the args
        */
        bool parse(int argc, const char * const argv[]) {
            errors.clear();
            others.clear();

            if (argc < 1) {
                errors.push_back("argument number must be longer than 0");
                return false;
            }
            if (prog_name == "")
                prog_name = argv[0];

            std::map<char, std::string> lookup;
            for (std::map<std::string, option_base*>::iterator p = options.begin();
                p != options.end(); p++) {
                if (p->first.length() == 0) continue;
                char initial = p->second->short_name();
                if (initial) {
                    if (lookup.count(initial) > 0) {
                        lookup[initial] = "";
                        errors.push_back(std::string("short option '") + initial + "' is ambiguous");
                        return false;
                    }
                    else lookup[initial] = p->first;
                }
            }

            for (int i = 1; i < argc; i++) {
                if (strncmp(argv[i], "--", 2) == 0) {
                    const char *p = strchr(argv[i] + 2, '=');
                    if (p) {
                        std::string name(argv[i] + 2, p);
                        std::string val(p + 1);
                        set_option(name, val);
                    }
                    else {
                        std::string name(argv[i] + 2);
                        if (options.count(name) == 0) {
                            errors.push_back("undefined option: --" + name);
                            continue;
                        }
                        if (options[name]->has_value()) {
                            if (i + 1 >= argc) {
                                errors.push_back("option needs value: --" + name);
                                continue;
                            }
                            else {
                                i++;
                                set_option(name, argv[i]);
                            }
                        }
                        else {
                            set_option(name);
                        }
                    }
                }
                else if (strncmp(argv[i], "-", 1) == 0) {
                    if (!argv[i][1]) continue;
                    char last = argv[i][1];
                    for (int j = 2; argv[i][j]; j++) {
                        last = argv[i][j];
                        if (lookup.count(argv[i][j - 1]) == 0) {
                            errors.push_back(std::string("undefined short option: -") + argv[i][j - 1]);
                            continue;
                        }
                        if (lookup[argv[i][j - 1]] == "") {
                            errors.push_back(std::string("ambiguous short option: -") + argv[i][j - 1]);
                            continue;
                        }

                        if (options[lookup[argv[i][j - 1]]]->has_value())
                        {
                            set_option(lookup[argv[i][j - 1]], &argv[i][j]);
                            last = 0;
                            break;
                        }
                        else
                        {
                            set_option(lookup[argv[i][j - 1]]);
                        }
                    }

                    if (last)
                    {
                        if (lookup.count(last) == 0) {
                            errors.push_back(std::string("undefined short option: -") + last);
                            continue;
                        }
                        if (lookup[last] == "") {
                            errors.push_back(std::string("ambiguous short option: -") + last);
                            continue;
                        }

                        if (i + 1 < argc && options[lookup[last]]->has_value()) {
                            set_option(lookup[last], argv[i + 1]);
                            i++;
                        }
                        else {
                            set_option(lookup[last]);
                        }
                    }
                }
                else {
                    others.push_back(argv[i]);
                }
            }

            for (std::map<std::string, option_base*>::iterator p = options.begin();
                p != options.end(); p++)
                if (!p->second->valid())
                    errors.push_back("need option: --" + std::string(p->first));

            return errors.size() == 0;
        }

        /**
        *parse the args and check
        */
        void parse_check(const std::string &arg) {
            if (!options.count("help"))
                add("help", '?', "print this message");
            check(0, parse(arg));
        }

        /**
        *parse the args and check
        */
        void parse_check(const std::vector<std::string> &args) {
            if (!options.count("help"))
                add("help", '?', "print this message");
            check(args.size(), parse(args));
        }

        /**
        *parse the args and check
        */
        void parse_check(int argc, char *argv[]) {
            if (!options.count("help"))
                add("help", '?', "print this message");
            check(argc, parse(argc, argv));
        }

        /**
        *get the parse error msg
        */
        std::string error() const {
            return errors.size() > 0 ? errors[0] : "";
        }

        /**
        *get the parse error msg
        */
        std::string error_full() const {
            std::ostringstream oss;
            for (size_t i = 0; i < errors.size(); i++)
                oss << errors[i] << std::endl;
            return oss.str();
        }

        /**
        *get the usage string
        */
        std::string usage() const {
            std::ostringstream oss;
            oss << "usage: " << prog_name << " ";
            for (size_t i = 0; i < ordered.size(); i++) {
                if (ordered[i]->must())
                    oss << ordered[i]->short_description() << " ";
            }

            oss << "[options] ... " << ftr << std::endl;
            oss << "options:" << std::endl;

            size_t max_width = 0;
            for (size_t i = 0; i < ordered.size(); i++) {
                max_width = max(max_width, ordered[i]->name().length());
            }
            for (size_t i = 0; i < ordered.size(); i++) {
                if (ordered[i]->short_name()) {
                    oss << "  -" << ordered[i]->short_name() << ", ";
                }
                else {
                    oss << "      ";
                }

                oss << "--" << ordered[i]->name();
                for (size_t j = ordered[i]->name().length(); j < max_width + 4; j++)
                    oss << ' ';
                oss << ordered[i]->description() << std::endl;
            }
            return oss.str();
        }

    private:

        void check(size_t argc, bool ok) {
            if ((argc == 1 && !ok) || exist("help")) {
#ifdef _CONSOLE
                std::cerr << usage();
#endif
                exit(0);
            }

            if (!ok) {
#ifdef _CONSOLE
                std::cerr << error() << std::endl << usage();
#endif
                exit(1);
            }
        }

        void set_option(const std::string &name) {
            if (options.count(name) == 0) {
                errors.push_back("undefined option: --" + name);
                return;
            }
            if (!options[name]->set()) {
                errors.push_back("option needs value: --" + name);
                return;
            }
        }

        void set_option(const std::string &name, const std::string &value) {
            if (options.count(name) == 0) {
                errors.push_back("undefined option: --" + name);
                return;
            }
            try
            {
                if (!options[name]->set(value)) {
                    errors.push_back("option value is invalid: --" + name + "=" + value);
                    return;
                }
            }
            catch (cmdline_error &e)
            {
                errors.push_back("option value is invalid: --" + name + "=" + value + " " + e.what());
                return;
            }
            catch (...) {
                errors.push_back("option value is invalid: --" + name + "=" + value);
                return;
            }
        }

        class option_base {
        public:
            virtual ~option_base() {}

            virtual bool has_value() const = 0;
            virtual bool set() = 0;
            virtual bool set(const std::string &value) = 0;
            virtual bool has_set() const = 0;
            virtual bool valid() const = 0;
            virtual bool must() const = 0;

            virtual const std::string &name() const = 0;
            virtual char short_name() const = 0;
            virtual const std::string &description() const = 0;
            virtual std::string short_description() const = 0;
        };

        class option_without_value : public option_base {
        public:
            option_without_value(const std::string &name,
                char short_name,
                const std::string &desc,
                bool need = false)
                :nam(name), snam(short_name), desc(desc), need(need), has(false) {
            }
            ~option_without_value() {}

            bool has_value() const { return false; }

            bool set() {
                has = true;
                return true;
            }

            bool set(const std::string &) {
                return false;
            }

            bool has_set() const {
                return has;
            }

            bool valid() const {
                if (need && !has) return false;
                return true;
            }

            bool must() const {
                return need;
            }

            const std::string &name() const {
                return nam;
            }

            char short_name() const {
                return snam;
            }

            const std::string &description() const {
                return desc;
            }

            std::string short_description() const {
                return "--" + nam;
            }

        private:
            std::string nam;
            char snam;
            std::string desc;
            bool has;
            bool need;
        };

        template <class T>
        class option_with_value : public option_base {
        public:
            option_with_value(const std::string &name,
                char short_name,
                bool need,
                const T &def,
                const std::string &desc)
                : nam(name), snam(short_name), need(need), has(false)
                , def(def), actual(def) {
                this->desc = full_description(desc);
            }
            ~option_with_value() {}

            const T &get() const {
                return actual;
            }

            bool has_value() const { return true; }

            bool set() {
                return false;
            }

            bool set(const std::string &value) {
                actual = read(value);
                has = true;
                return true;
            }

            bool has_set() const {
                return has;
            }

            bool valid() const {
                if (need && !has) return false;
                return true;
            }

            bool must() const {
                return need;
            }

            const std::string &name() const {
                return nam;
            }

            char short_name() const {
                return snam;
            }

            const std::string &description() const {
                return desc;
            }

            std::string short_description() const {
                return "--" + nam + "=" + readable_typename<typename is_container<T>::type, is_container<T>::value>::name();
            }

        protected:
            std::string full_description(const std::string &desc) {
                return
                    desc + " (" + readable_typename<typename is_container<T>::type, is_container<T>::value>::name() +
                    (need ? "" : " [=" + lexical_cast<std::string>(def) + "]")
                    + ")";
            }

            virtual T read(const std::string &s) = 0;

            std::string nam;
            char snam;
            bool need;
            std::string desc;

            bool has;
            T def;
            T actual;
        };

        template <class T, class F>
        class option_with_value_with_reader : public option_with_value<T> {
        public:
            option_with_value_with_reader(const std::string &name,
                char short_name,
                bool need,
                const T def,
                const std::string &desc,
                F reader)
                : option_with_value<T>(name, short_name, need, def, desc), reader(reader) {
            }

        private:
            T read(const std::string &s) {
                return reader(s);
            }

            F reader;
        };

        std::map<std::string, option_base*> options;
        std::vector<option_base*> ordered;
        std::string ftr;

        std::string prog_name;
        std::vector<std::string> others;

        std::vector<std::string> errors;
    };
}

#endif