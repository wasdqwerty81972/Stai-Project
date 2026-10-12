import 'package:flutter/material.dart';

import 'privacy_onboarding.dart';
import 'shell.dart';

class SvsCyberMobileApp extends StatelessWidget {
  const SvsCyberMobileApp({super.key, this.firstRunStore});

  final PrivacyOnboardingStore? firstRunStore;

  static const _background = Color(0xFF090D16);
  static const _surface = Color(0xFF111827);
  static const _accent = Color(0xFF62E6D2);

  @override
  Widget build(BuildContext context) {
    final colorScheme = ColorScheme.fromSeed(
      seedColor: _accent,
      brightness: Brightness.dark,
      surface: _surface,
    );

    return MaterialApp(
      title: 'SVS-Cyber Mobile',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorScheme: colorScheme,
        scaffoldBackgroundColor: _background,
        appBarTheme: const AppBarTheme(
          backgroundColor: _background,
          surfaceTintColor: Colors.transparent,
          centerTitle: false,
        ),
        cardTheme: CardThemeData(
          color: _surface,
          elevation: 0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(20),
            side: BorderSide(color: Colors.white.withValues(alpha: 0.07)),
          ),
        ),
        navigationBarTheme: NavigationBarThemeData(
          backgroundColor: _surface,
          indicatorColor: _accent.withValues(alpha: 0.16),
          labelTextStyle: WidgetStateProperty.resolveWith((states) {
            return TextStyle(
              fontSize: 11,
              fontWeight: states.contains(WidgetState.selected)
                  ? FontWeight.w700
                  : FontWeight.w500,
            );
          }),
        ),
      ),
      home: PrivacyOnboardingGate(
        store: firstRunStore ?? MethodChannelPrivacyOnboardingStore(),
        appBuilder: (_) => const MobileShell(),
      ),
    );
  }
}
