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

from django.db import models


class AutoCleanModel(models.Model):
    class Meta:
        abstract = True

    def _init_states(self):
        self.initial_state = self.current_state

        self.cleaned_state = {} if not self.pk else self.initial_state.copy()
        self.saved_state = {} if not self.pk else self.initial_state.copy()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._init_states()

    @property
    def current_state(self):
        return {
            field.name: self.__dict__[field.attname]
            for field in self._meta.fields
            if field.attname in self.__dict__
        }

    @staticmethod
    def _states_diff(state, other_state):
        return {key: value for key, value in other_state.items() if value != state[key]}

    def get_dirty_fields(self):
        return self._states_diff(self.current_state, self.cleaned_state)

    def get_unsaved_fields(self):
        if not self.saved_state:
            return list(self.current_state.keys())

        return list(self._states_diff(self.current_state, self.saved_state).keys())

    @property
    def is_cleaned(self):
        if not getattr(self, ".cleaned", False):
            return False

        return not self.get_dirty_fields()

    @is_cleaned.setter
    def is_cleaned(self, value):
        if value:
            self.cleaned_state = self.current_state.copy()

        setattr(self, ".cleaned", value)

    def save(self, *args, **kwargs):
        if not self.is_cleaned:
            self.full_clean()

        super().save(*args, **kwargs)

        self.initial_state = self.current_state.copy()
        if kwargs.get("update_fields") is None:
            self.saved_state = self.current_state.copy()
        else:
            for field in kwargs["update_fields"]:
                if field not in self.current_state:
                    continue

                self.saved_state[field] = self.current_state[field]

    def refresh_from_db(self, *args, **kwargs):
        super().refresh_from_db(*args, **kwargs)

        self._init_states()

    def full_clean(self, *args, **kwargs):
        if self.is_cleaned:
            return

        super().full_clean(*args, **kwargs)

        self.is_cleaned = True


class FakePK(int):
    def is_fake(self):
        return True
