#ifndef SMART_RESOURCE_H_INCLUDED
#define SMART_RESOURCE_H_INCLUDED

/**
SmartResource is used to load the resource that just need success load once. it just need to inherit the Resourc class, and realize the
LoadResource and UnloadResource interface, then use SmartResource class to manage the resource.
*/

#include <mutex>

class SmartResource;

class Resource
{
friend class SmartResource;

public:
    Resource() : res_mutex(), res_ref_count(0), is_res_load(false){}
    ~Resource(){}

    Resource(const Resource&) = delete;
    Resource(Resource&&) = delete;
    Resource& operator=(const Resource&) = delete;
    Resource& operator=(Resource&&) = delete;

protected:
    virtual bool LoadResource() 
    {
        return true;
    }
    virtual void UnloadResource()
    {
        return;
    }

private:
    std::mutex    res_mutex;
    unsigned int  res_ref_count;
    bool          is_res_load;
};

class SmartResource
{
public:
    SmartResource(Resource &res) : m_res(res)
    {
        std::unique_lock<std::mutex> lck(m_res.res_mutex);
        if (m_res.res_ref_count++ && m_res.is_res_load)
        {
            return;
        }
        m_res.is_res_load = true;
        try
        {
            if (!m_res.LoadResource())
            {
                m_res.is_res_load = false;
            }
        }
        catch (...)
        {
            m_res.is_res_load = false;
        }
    }
    ~SmartResource()
    {
        std::unique_lock<std::mutex> lck(m_res.res_mutex);
        if (--m_res.res_ref_count || !m_res.is_res_load)
        {
            return;
        }
        try
        {
            m_res.UnloadResource();
        }
        catch (...)
        {

        }
        m_res.is_res_load = false;
    }

    SmartResource(const SmartResource&) = delete;
    SmartResource(SmartResource&&) = delete;
    SmartResource& operator=(const SmartResource&) = delete;
    SmartResource& operator=(SmartResource&&) = delete;

private:
    Resource &m_res;
};

#endif