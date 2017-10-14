#ifndef RESOURCE_POOL_H_INCLUDED
#define RESOURCE_POOL_H_INCLUDED

#include <mutex>

template<typename T>
class Resource
{
public:
    Resource() : data()
    {
        next = NULL;
    }

    ~Resource()
    {
        if (next) {
            delete next;
            next = NULL;
        }
    }

    Resource(const Resource&) = delete;
    Resource& operator = (const Resource&) = delete;

    /**
    *get the resource data
    */
    T& Get()
    {
        return data;
    }

private:
    T data;

public:
    Resource<T> *next;
};

template<typename T>
class ResourcePool
{
    /**
    *all resource will not be free until pool free
    */
public:
    ResourcePool()
    {
        free = NULL;
    }

    ~ResourcePool()
    {
        if (free) {
            delete free;
            free = NULL;
        }
    }

    ResourcePool(const ResourcePool&) = delete;
    ResourcePool& operator = (const ResourcePool&) = delete;

    /**
    *retrive a resource
    */
    Resource<T>* GetResource()
    {
        if (!free) {
            return new Resource<T>();
        }
        std::unique_lock<std::mutex> lck(lock);
        Resource<T>* r = free;
        free = free->next;
        r->next = NULL;
        return r;
    }

    /**
    *free a resource
    */
    void FreeResource(Resource<T>* res)
    {
        if (!res) {
            return;
        }
        std::unique_lock<std::mutex> lck(lock);
        Resource<T> *head = free;
        free = res;
        Resource<T> **next = &free->next;
        while (*next) {
            next = &((*next)->next);
        }
        *next = head;
    }

private:
    std::mutex lock;
    Resource<T> *free;
};

#endif
