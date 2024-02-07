#  Copyright 2024 Pressinfra SRL
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import enum


class PermEnum(enum.StrEnum):
    def __repr__(self):
        if not hasattr(self, "auth_scheme"):
            return super().__repr__()

        value_repr = self.__class__._value_repr_ or repr

        return "<%s.%s.%s: %s>" % (
            self.auth_scheme.__name__,
            self.__class__.__name__,
            self._name_,
            value_repr(self._value_),
        )

    @classmethod
    def values(cls):
        return list(cls)
