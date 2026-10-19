"""Optional pinned backend bridge; no installed app, GPIO, SPI or refresh.

Set INKYOS_FACTORY_DISPLAY_BACKEND_ROOT to a backend checkout at BACKEND_COMMIT.
Missing opt-in is an explicit skip; an invalid supplied checkout fails. Only the
four pinned display modules execute. Image imports, auto() and data_dir() are
inert seams; tuple/version/profile guards, BUSY selection and barrier reads are
the real backend code. This proves selection, never physical display output.
"""
import builtins
import hashlib
import os
import subprocess
import sys
import unittest
from contextlib import contextmanager
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock, patch

from test_factory_runtime_contract import ContractFixture, load_module, runtime

BACKEND_ENV = 'INKYOS_FACTORY_DISPLAY_BACKEND_ROOT'
BACKEND_COMMIT = '302ff5d3fb85b220b90af5f2e7eb1e00343fb4c4'
SOURCE_PINS = {
    'errors': '744120923d7190927ec61854fb4de560a3432d203dedfd2a461b599d0f5316fc',
    'confirmation': 'fb7f5ffee28cc19f52b4a68c686d4aaf72ea0b327245e1f722f32601b8161efa',
    'busy': '136259a7dc137fe4daf242cee98a6bb776f87fb49eefc7bdd1a50390790077e7',
    'display': 'de0fbacd6fcc4cc21424e25352e06b77ea65cbfbdb72a3cc4eb9cb94e13532a8',
}
launcher = load_module('writer_launcher_display_bridge_test', 'scripts/writer-launcher.py')


class CapturedExec(BaseException):
    pass


def package(name):
    module = ModuleType(name)
    module.__path__ = []
    return module


class FactoryDisplayProfileBridgeTests(ContractFixture):
    @classmethod
    def setUpClass(cls):
        supplied = os.environ.get(BACKEND_ENV)
        if not supplied:
            raise unittest.SkipTest(f'set {BACKEND_ENV} to explicitly test backend {BACKEND_COMMIT}')
        cls.backend_root = Path(supplied).resolve(strict=True)
        commit = subprocess.check_output(
            ['git', '-C', str(cls.backend_root), 'rev-parse', 'HEAD'],
            env={**os.environ, 'GIT_OPTIONAL_LOCKS': '0'}, text=True, timeout=10,
        ).strip()
        if commit != BACKEND_COMMIT:
            raise AssertionError(f'backend commit must be {BACKEND_COMMIT}, got {commit}')
        cls.sources = {}
        for name, expected in SOURCE_PINS.items():
            path = cls.backend_root / 'server/inky_web/inky' / (name + '.py')
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected:
                raise AssertionError(f'backend source pin mismatch: {path}')
            cls.sources[name] = (path, raw)

    def setUp(self):
        super().setUp()
        self.contract_value, _ = self.ready(self.full_candidate())
        self.display_state = self.base / 'display-state'
        self.display_state.mkdir()
        seam = patch.object(launcher, 'runtime', runtime)
        seam.start()
        self.addCleanup(seam.stop)

    def main_environment(self):
        captured = {}

        def capture(path, argv, environ):
            self.assertEqual((path, tuple(argv)), (launcher.ARGV['main'][0], launcher.ARGV['main']))
            self.assertTrue(os.get_inheritable(int(environ['INKYOS_WRITER_LEASE_FD'])))
            captured.update(environ)
            raise CapturedExec()

        with self.assertRaises(CapturedExec):
            launcher.launch('main', _contract=self.contract_value,
                            _identity=self.identity('main'), _execve=capture,
                            _environ={'INKY_STUDIO_DISPLAY_PROFILE': 'untrusted-panel',
                                      'INKY_STUDIO_DISPLAY_MODE': 'mock'})
        return captured

    @contextmanager
    def backend(self, environ, *, width=800, height=480, variant=20, color=4,
                driver_width=800, driver_height=480, module='inky.inky_ac073tc1a', installed='2.5.0'):
        driver = type('Inky', (), {'__module__': module})()
        driver.width, driver.height = driver_width, driver_height
        driver.eeprom = SimpleNamespace(width=width, height=height, display_variant=variant, color=color)
        driver.show = Mock(side_effect=AssertionError('refresh is forbidden'))
        driver.set_image = Mock(side_effect=AssertionError('image transfer is forbidden'))
        auto = ModuleType('inky.auto')
        auto.auto = Mock(return_value=driver)
        db = ModuleType('inky_web.db')
        db.data_dir = lambda: self.display_state
        modules = {'inky_web': package('inky_web'), 'inky_web.inky': package('inky_web.inky'),
                   'inky_web.db': db, 'inky': package('inky'), 'inky.auto': auto,
                   'PIL': package('PIL'), 'PIL.Image': ModuleType('PIL.Image'),
                   'PIL.ImageEnhance': ModuleType('PIL.ImageEnhance')}
        original_import = builtins.__import__
        forbidden_imports = []

        def bounded_import(name, *args, **kwargs):
            if (name.split('.')[0] in {'inky', 'gpiod', 'gpiodevice', 'spidev', 'smbus', 'smbus2'}
                    and name != 'inky.auto'):
                forbidden_imports.append(name)
                raise AssertionError('hardware import is forbidden: ' + name)
            return original_import(name, *args, **kwargs)

        def version(name):
            if name == 'inky':
                return installed
            raise PackageNotFoundError(name)

        with patch.dict(sys.modules, modules), patch.dict(os.environ, environ, clear=True), \
                patch.object(builtins, '__import__', side_effect=bounded_import):
            for name, (path, raw) in self.sources.items():
                fullname = 'inky_web.inky.' + name
                loaded = ModuleType(fullname)
                loaded.__file__, loaded.__package__ = str(path), 'inky_web.inky'
                sys.modules[fullname] = loaded
                exec(compile(raw, str(path), 'exec'), loaded.__dict__)  # noqa: S102 - exact SHA-256-pinned bytes only
            display = sys.modules['inky_web.inky.display']
            with patch.object(display, 'version', side_effect=version):
                try:
                    yield display, auto.auto, driver
                finally:
                    self.assertEqual(forbidden_imports, [])
                    driver.show.assert_not_called()
                    driver.set_image.assert_not_called()
                    self.assertEqual(list(self.display_state.iterdir()), [])

    def assert_unavailable(self, module, display):
        self.assertEqual(display.status()['state'], 'error')
        self.assertFalse(display.is_mock)
        with self.assertRaises(module.DisplayUnavailableError):
            display.require_available()

    def test_real_main_environment_accepts_ac073_color4_without_changing_eeprom(self):
        environ = self.main_environment()
        with self.backend(environ) as (module, auto, driver):
            before = vars(driver.eeprom).copy()
            display = module.DisplayController()
            display.initialize()
            display.require_available()
            self.assertEqual(display.status()['mode'], 'hardware')
            self.assertEqual(display.status()['profile'], 'ac073-800x480-timed-wait')
            self.assertEqual(display.status()['state'], 'ready')
            self.assertEqual(display.status()['driver']['color_raw'], 4)
            self.assertEqual(display.status()['busy_monitor'], 'ac073_2.5.0')
            self.assertEqual((display.spec.width, display.spec.height), (800, 480))
            self.assertFalse(display.is_mock)
            self.assertEqual(vars(driver.eeprom), before)
            auto.assert_called_once_with(ask_user=False, verbose=False)

    def test_same_color4_tuple_is_refused_without_explicit_profile(self):
        environ = self.main_environment()
        del environ['INKY_STUDIO_DISPLAY_PROFILE']
        with self.backend(environ) as (module, _, _):
            display = module.DisplayController()
            display.initialize()
            self.assert_unavailable(module, display)

    def test_profile_does_not_relax_exact_tuple_or_driver_guards(self):
        environ = self.main_environment()
        for overrides in ({'width': 600}, {'height': 448}, {'variant': 26}, {'color': 6},
                          {'width': 800.0}, {'height': 480.0}, {'variant': 20.0}, {'color': 4.0},
                          {'variant': True}, {'driver_width': 600}, {'driver_height': 448},
                          {'module': 'inky.inky_e673'}):
            with self.subTest(overrides=overrides), self.backend(environ, **overrides) as (module, _, _):
                display = module.DisplayController()
                display.initialize()
                self.assert_unavailable(module, display)

    def test_profile_does_not_relax_pinned_driver_version(self):
        environ = self.main_environment()
        for installed in ('2.3.0', '2.4.0', '2.5.1'):
            with self.subTest(installed=installed), self.backend(environ, installed=installed) as (module, _, _):
                display = module.DisplayController()
                display.initialize()
                self.assert_unavailable(module, display)
                self.assertEqual(display.status()['driver']['inky_version'], installed)

    def test_profile_still_requires_hardware_mode_and_known_profile(self):
        environ = self.main_environment()
        for changes in ({'INKY_STUDIO_DISPLAY_MODE': 'mock'},
                        {'INKY_STUDIO_DISPLAY_MODE': 'invalid'},
                        {'INKY_STUDIO_DISPLAY_PROFILE': 'another-panel'}):
            with self.subTest(changes=changes), self.backend({**environ, **changes}) as (module, auto, _):
                with self.assertRaises(ValueError):
                    module.DisplayController()
                auto.assert_not_called()


if __name__ == '__main__':
    unittest.main()
