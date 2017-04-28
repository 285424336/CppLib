#ifndef EVENT_ENGINE_H
#define EVENT_ENGINE_H

#if defined(_MSC_VER)
#include <Windows.h>
#include <threadpool\ThreadPool.h>
#elif defined(__GNUC__)
#include <threadpool/ThreadPool.h>
#else
#error unsupported compiler
#endif
#include <map>
#include <vector>
#include <functional>
#include <mutex>

class EventHub
{
public:
    class ID
    {
    public:
        size_t type_hash;
        std::shared_ptr<std::function<void(u_int, void *)>> id;
    };
public:
    EventHub(u_int pool_size = 0) : pool(std::make_shared<ThreadPool>(pool_size)), map_mutex(), listeners()
    {
    }
    virtual ~EventHub()
    {

    }
    /**
    *Subscribe the event listener
    *event: the event want to listen
    *f: the callback
    *T: the type, if T is void, then it will receive all type of this event
    */
    template <typename T>
    ID SubscribeEvent(u_int event, const std::function<void(u_int, T *)> &f)
    {
        typedef typename std::remove_cv<T>::type type;
        size_t type_hash = typeid(type).hash_code();
        std::shared_ptr<std::function<void(u_int, void *)>> ptr;
        {
            std::unique_lock<std::mutex> lock(map_mutex);
            ptr = std::make_shared<std::function<void(u_int, void *)>>([f](u_int var1, void *var2)
            {
                f(var1, (type *)var2);
            });
            listeners[event][type_hash].emplace_back(ptr);
        }
        return ID{ type_hash, ptr };
    }

    /**
    *unsubscribe the event listener
    *event: the event not want to listen
    *id: id return by RegisterEvent
    *note: after call, id will be invalid
    */
    void UnSubscribeEvent(u_int event, ID &&id)
    {
        if (!id.id) return;
        {
            std::unique_lock<std::mutex> lock(map_mutex);
            auto it = listeners[event][id.type_hash].begin();
            auto end = listeners[event][id.type_hash].end();
            for (; it != end; it++)
            {
                if (*it == id.id) break;
            }
            if (it != end) listeners[event][id.type_hash].erase(it);
        }
        id.id.reset();
    }

    /**
    *dispatch the event to the listerners.
    *event: the event that need to dispatch
    *s: the event parameter
    *note: the parameter s type must have copy instructer
    */
    template <typename T>
    bool DispatchEvent(u_int event, T &&s)
    {
        typedef typename std::remove_reference<T>::type type;
        size_t type_hash = typeid(type).hash_code();
        bool ret = true;
        auto ptr = std::make_shared<type>(std::forward<T>(s));
        std::unique_lock<std::mutex> lock(map_mutex);
        for (auto f : listeners[event][type_hash])
        {
            try
            {
                pool->enqueue([event, f, ptr]
                {
                    (*f)(event, (void *)ptr.get());
                });
            }
            catch (...)
            {
                ret = false;
            }
        }

        for (auto f : listeners[event][typeid(void).hash_code()])
        {
            try
            {
                pool->enqueue([event, f, ptr]
                {
                    (*f)(event, (void *)ptr.get());
                });
            }
            catch (...)
            {
                ret = false;
            }
        }
        return ret;
    }

    /**
    *reset the thread pool size
    */
    void ReSetPool(u_int pool_size)
    {
        std::unique_lock<std::mutex> lock(map_mutex);
        pool = std::make_shared<ThreadPool>(pool_size);
    }

private:
    std::shared_ptr<ThreadPool> pool;
    std::mutex map_mutex;
    std::map<u_int, std::map<size_t, std::vector<std::shared_ptr<std::function<void(u_int, void *)>>>>> listeners;
};

#endif // !EVENT_ENGINE_H
