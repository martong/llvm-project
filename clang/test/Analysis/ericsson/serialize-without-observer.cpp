// RUN: %clang_analyze_cc1 -analyzer-checker=ericsson.mtas.SerializeWithoutObserver -Wno-everything -verify %s
namespace NodeControlSupport
{
  class ISerializerObserver {};
}

class X {// expected-warning {{Serialization without inheriting from ISerializerObserver}}
  int serialize() { return 0; }
};

class Y : public NodeControlSupport::ISerializerObserver {
  int serialize() { return 0; }
};
