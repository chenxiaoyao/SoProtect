#ifndef __LINKED_LIST_H__
#define __LINKED_LIST_H__

#include "extra_defines.h"

template<typename T>
struct LinkedListEntry {
  LinkedListEntry<T>* next;
  T* element;
};

/*
 * Represents linked list of objects of type T
 */
template<typename T, typename Allocator>
class LinkedList {
 public:
  LinkedList() : head_(nullptr), tail_(nullptr) {}

  void push_front(T* const element) {
    LinkedListEntry<T>* new_entry = Allocator::alloc();
    new_entry->next = head_;
    new_entry->element = element;
    head_ = new_entry;
    if (tail_ == nullptr) {
      tail_ = new_entry;
    }
  }

  void push_back(T* const element) {
    LinkedListEntry<T>* new_entry = Allocator::alloc();
    new_entry->next = nullptr;
    new_entry->element = element;
    if (tail_ == nullptr) {
      tail_ = head_ = new_entry;
    } else {
      tail_->next = new_entry;
      tail_ = new_entry;
    }
  }

  T* pop_front() {
    if (head_ == nullptr) {
      return nullptr;
    }

    LinkedListEntry<T>* entry = head_;
    T* element = entry->element;
    head_ = entry->next;
    Allocator::free(entry);

    if (head_ == nullptr) {
      tail_ = nullptr;
    }

    return element;
  }

  void clear() {
    while (head_ != nullptr) {
      LinkedListEntry<T>* p = head_;
      head_ = head_->next;
      Allocator::free(p);
    }

    tail_ = nullptr;
  }

  template<typename F>
  void for_each(F&& action) {
    for (LinkedListEntry<T>* e = head_; e != nullptr; e = e->next) {
      if (e->element != nullptr) {
        action(e->element);
      }
    }
  }

  template<typename F>
  void remove_if(F&& predicate) {
    for (LinkedListEntry<T>* e = head_; e != nullptr; e = e->next) {
      if (e->element != nullptr && predicate(e->element)) {
        e->element = nullptr;
      }
    }
  }

  bool contains(const T* el) {
    for (LinkedListEntry<T>* e = head_; e != nullptr; e = e->next) {
      if (e->element != nullptr && e->element == el) {
        return true;
      }
    }
    return false;
  }

 private:
  LinkedListEntry<T>* head_;
  LinkedListEntry<T>* tail_;
  DISALLOW_COPY_AND_ASSIGN(LinkedList);
};

#endif // __LINKED_LIST_H

