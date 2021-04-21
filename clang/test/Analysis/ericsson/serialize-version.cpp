// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.mtas.SerializeVersion -Wno-everything -verify %s
#include "Inputs/system-header-simulator-cxx.h"
#include "Inputs/system-header-simulator-cxx-string.h"

#define NULL 0

// Interfaces
class ISerialize;

class ISerializeObserver
{
public:
  virtual void serialize(ISerialize * iSerialize) const = 0;
};

class ISerializerObserver : public ISerializeObserver
{
public:
  virtual const std::string & getClassName() const = 0;
  virtual unsigned int getClassVersion() const = 0;
};

// Test classes
class ADummy : public ISerializerObserver
{
  int a = 2;
public:
  virtual void serialize(ISerialize * iSerialize);
  virtual unsigned int getClassVersion() { return a; }
};

class BDummy : public ISerializerObserver
{
  enum {
     SERIALIZE_ED2_WP412   = 0,
     SERIALIZE_ED3_WP430   = 1,
     SERIALIZE_ED3_WP438   = 2,
     SERIALIZE_ED3_WP438D2 = 3,
     SERIALIZE_ED3_HL56101 = 10,
     SERIALIZE_WP454       = 20,
  };
public:
  virtual void serialize(ISerialize * iSerialize) const {}
  virtual unsigned int getClassVersion() const { return SERIALIZE_WP454; }
};

class CDummy : public ISerializerObserver
{
  enum NamedEnum {
     SERIALIZE_ED2_WP412   = 0,
     SERIALIZE_ED3_WP430   = 1,
     SERIALIZE_ED3_WP438   = 2
  };
  NamedEnum m_version = SERIALIZE_ED2_WP412;
public:
  virtual void serialize(ISerialize * iSerialize) const {}
  virtual unsigned int getClassVersion() const { return m_version; }
};

class DDummy : public ISerializerObserver // expected-warning {{Missing or not valid getClassVersion method}} // warning
{
public:
  virtual void serialize(ISerialize * iSerialize) const {}
  virtual unsigned int getClassVersion() const { return 0; }
};

class EDummy : public ISerializerObserver  // expected-warning {{Missing or not valid getClassVersion method}} // warning
{
public:
  virtual void serialize(ISerialize * iSerialize) const {}
  virtual unsigned int getClassVersion() const { return NULL; }
};

class FDummy : public ISerializerObserver
{
  int a = 2;
public:
  virtual void serialize(ISerialize * iSerialize) const {}
  virtual unsigned int getClassVersion() const { return a; }
};

class GDummy : public ISerializerObserver   // expected-warning {{Missing or not valid getClassVersion method}} // warning
{
public:
  virtual void serialize(ISerialize * iSerialize) const {}

};

class HDummy : public ISerializerObserver // expected-warning {{Missing or not valid getClassVersion method}} // warning
{
public:
  virtual void serialize(ISerialize * iSerialize) const {}
  virtual unsigned int getClassVersion() const { return 'c'; }
};

class IDummy : public ISerializerObserver // expected-warning {{Missing or not valid getClassVersion method}} // warning
{
  int a = 2;
public:
  virtual void serialize(ISerialize * iSerialize) const {}
  virtual unsigned int getClassVersion() { return a; }
};

class JDummy : public ISerializerObserver
{
public:
  virtual void serialize(int * iSerialize) const {}
  virtual unsigned int getClassVersion() const { return 2; }
};

class KDummy : public ISerializerObserver
{
public:
  virtual void serialize(ISerialize * iSerialize) const {}
  virtual unsigned int getClassVersion() const;
};

class LDummy
{
public:
  virtual void serialize(ISerialize * iSerialize) const {}
  virtual unsigned int getClassVersion() const;
};

class MDummy
{
public:
  int f(unsigned int a) const;
  virtual void serialize(ISerialize * iSerialize) const;
  virtual unsigned int getClassVersion() const { return f(0); }
};
