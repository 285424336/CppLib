#ifndef SELECT_H_INCLUDED
#define SELECT_H_INCLUDED

namespace stdex
{
    /*
    meta template to select entry of variadic template arguments:
    select<int, 0, 2, 5, 3>::value == 2;
    select<int, 1, 2, 5, 3>::value == 5;
    select<int, 2, 2, 5, 3>::value == 3;
    */

    template <typename T, unsigned int index, T X1, T... XN>
    struct select
    {
        static constexpr T value = select<T, (index - 1), XN...>::value;
    };

    template <typename T, T X1, T... XN>
    struct select<T, 0, X1, XN...>
    {//when index decrease to zero, then successfull selected
        static constexpr T value = X1;
    };
}

#endif